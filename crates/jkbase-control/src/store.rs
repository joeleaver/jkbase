use crate::auth::{self, ApiToken, Tenant};
use crate::jose;
use anyhow::{Context, Result};
use base64::Engine;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

/// base64url (no pad) — the encoding for jkbase-Auth key material at rest (private seed + public
/// key) and in emitted JWKs.
const B64URL: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::URL_SAFE_NO_PAD;

const PROJECTS: TableDefinition<&str, &[u8]> = TableDefinition::new("projects");
const VM_ALLOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("vm_allocations");
const TENANTS: TableDefinition<&str, &[u8]> = TableDefinition::new("tenants");
const API_TOKENS: TableDefinition<&str, &[u8]> = TableDefinition::new("api_tokens");
const SECRETS: TableDefinition<&str, &[u8]> = TableDefinition::new("secrets");
const SNAPSHOTS: TableDefinition<&str, &[u8]> = TableDefinition::new("snapshots");
const DEPLOYMENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("deployments");
const BUILDS: TableDefinition<&str, &[u8]> = TableDefinition::new("builds");
const DOMAINS: TableDefinition<&str, &[u8]> = TableDefinition::new("domains");
const SCHEDULES: TableDefinition<&str, &[u8]> = TableDefinition::new("schedules");
const USAGE: TableDefinition<&str, &[u8]> = TableDefinition::new("usage");
const QUOTAS: TableDefinition<&str, &[u8]> = TableDefinition::new("quotas");
const QUOTA_STATUS: TableDefinition<&str, &[u8]> = TableDefinition::new("quota_status");
/// Per-TENANT resource limits, keyed by `tenant_id`. The platform's first
/// tenant-scoped quota (all others are per-project); today it holds only the
/// warm-VM cap. Absent override -> [`DEFAULT_TENANT_QUOTA`].
const TENANT_QUOTAS: TableDefinition<&str, &[u8]> = TableDefinition::new("tenant_quotas");
/// Per-project L4 EGRESS limits, keyed by `project_id`. Absent override -> the platform defaults
/// resolved from `L4PlaneLimits`. Platform-admin-set only: these numbers govern how much a project
/// may reply, so a tenant that could set its own would simply set them to infinity.
const L4_EGRESS_LIMITS: TableDefinition<&str, &[u8]> = TableDefinition::new("l4_egress_limits");
/// Per-project connected-repo trigger credentials (build · D): the git-push
/// token fingerprint, bound to the owning tenant. Kept out of the app-`SECRETS`
/// table (those are tenant env vars) so the two never leak into each other.
const REPO_TRIGGERS: TableDefinition<&str, &[u8]> = TableDefinition::new("repo_triggers");
/// Tenant S3 access keys for the object store, keyed by the (globally unique)
/// access-key id → the full [`AccessKey`] record (incl. the secret, which must be
/// recoverable to verify SigV4 signatures). This is the O(1) lookup the object-store
/// auth path hits on every request, given only the access-key id from a signature.
const ACCESS_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("access_keys");
/// Secondary index for per-project list/revoke, keyed `{project_id}:{access_key_id}`
/// (the `:` makes the prefix exact, like `SECRETS`). Value is the access-key id, so a
/// project scan yields its ids without a full `ACCESS_KEYS` walk. Both tables are
/// written in one txn so they never diverge.
const ACCESS_KEYS_BY_PROJECT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("access_keys_by_project");

/// Managed-DB reach-plane access keys — a credential keyspace ENTIRELY SEPARATE from the
/// S3 `ACCESS_KEYS` above ([R2]). A distinct table + a distinct `JKBD` akid prefix means an
/// object-store key can never resolve on the DB reach path and a DB key can never sign
/// SigV4 — a partition, not a shared `scope` flag one default-value bug from cross-streaming.
/// Records store ONLY a sha256 fingerprint of the secret ([R4]), never the secret. Mirrors
/// the primary + per-project-index split so listing/teardown stay O(keys-for-this-project).
const DB_ACCESS_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("db_access_keys");
const DB_ACCESS_KEYS_BY_PROJECT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("db_access_keys_by_project");
/// Per-project managed-DB reach-plane **splice secret** ([R3]): the host→agent shared
/// secret the edge presents on the `/_jkbase/db` upgrade and the in-VM agent verifies
/// before splicing to the loopback DB. Generated host-side at deploy and written into
/// the per-VM metadata image (which the host never reads back — it never mounts the
/// guest fs), so the edge needs an independent copy here to present it. `project_id` →
/// secret; overwritten each deploy (like the own-bucket binding), purged on teardown.
const DB_SPLICE: TableDefinition<&str, &[u8]> = TableDefinition::new("db_splice_secret");
/// Per-project **L4 transit secret** (`jkbl_…`): the host↔guest shared key authenticating
/// every L4 UDP transit datagram. Minted sticky (once per project, reused across redeploys)
/// so the host relay's copy and the agent's baked `_l4.json` copy always agree. Distinct
/// from `DB_SPLICE` — L4 is not DB-coupled. See docs/managed-l4-udp-ingress-design.md §3(a-auth).
const L4_TRANSIT: TableDefinition<&str, &[u8]> = TableDefinition::new("l4_transit_secret");
/// Per-project rhypedb **admin token** ([RB1]): the per-deploy `RHYPEDB_ADMIN_TOKEN` the
/// agent injects into the DB env to authorize `/admin/backup/stream`. Like [`DB_SPLICE`],
/// it is generated host-side at deploy, baked into the per-VM image (which the host never
/// reads back), so the backup executor needs an independent copy here. `project_id` →
/// token; overwritten each deploy, purged on teardown.
const DB_ADMIN_TOKEN: TableDefinition<&str, &[u8]> = TableDefinition::new("db_admin_token");
/// Per-project managed-DB **deployed tier** (`"colocated"` | `"dedicated"`), stamped on each
/// successful deploy. The deploy path reads it BEFORE tearing down the old VM to refuse an
/// in-place tier FLIP (which would strand the old-tier DB data on its disk — colocated data on
/// `{id}.img`, dedicated data on `{id}.db.img` — and silently start an empty DB or orphan the
/// sibling VM). Absent ⇒ first deploy / pre-P2 project ⇒ no flip to detect. Purged on teardown so
/// a recreated same-slug project starts fresh.
const DB_DEPLOYED_TIER: TableDefinition<&str, &[u8]> = TableDefinition::new("db_deployed_tier");
/// Per-project managed-DB **backup catalog** (primary, key = `backup_id`) + its
/// per-project index (`"{project_id}:{backup_id}"` → `backup_id`), mirroring the
/// [`DB_ACCESS_KEYS`] primary+index split so list/teardown stay O(backups-for-this-project)
/// and a tenant can't resolve another project's backup by guessing an id. Rows hold only
/// metadata (the tar lives in the platform object store); purged on teardown.
const DB_BACKUPS: TableDefinition<&str, &[u8]> = TableDefinition::new("db_backups");
const DB_BACKUPS_BY_PROJECT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("db_backups_by_project");
/// jkbase-Auth (P3) per-project **signing-key state**, keyed by `project_id` → [`SigningKeyState`]:
/// the CURRENT Ed25519 keypair (32-byte private seed recoverable at rest, host-only — P0-AUTH-2)
/// plus the set of rotated-out *public* keys still inside their overlap windows so tokens minted
/// under them still verify (P0-AUTH-4). Purged on teardown so a recreated same-slug project starts
/// with a fresh key.
const AUTH_SIGNING_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_signing_keys");
/// jkbase-Auth **issuer keys** — the `jkbk_` bearer a tenant's own backend presents to the `auth.`
/// mint endpoint to have a per-end-user JWT signed. A keyspace ENTIRELY SEPARATE from the S3
/// (`JKBA`) and DB (`JKBD`) keys: distinct `jkbk_` prefix + distinct table. Keyed by the secret's
/// sha256 fingerprint for an O(1) auth lookup (the secret itself is never stored — [R4] discipline);
/// the record carries `project_id`+`tenant_id` for owner-rebind (P0-AUTH-3).
const AUTH_ISSUER_KEYS: TableDefinition<&str, &[u8]> = TableDefinition::new("auth_issuer_keys");
/// Secondary index for per-project list/revoke/teardown, keyed `{project_id}:{key_id}` → the
/// primary's fingerprint. Mirrors the [`DB_ACCESS_KEYS_BY_PROJECT`] split so list/teardown stay
/// O(keys-for-this-project) and one project can't address another's key by guessing an id.
const AUTH_ISSUER_KEYS_BY_PROJECT: TableDefinition<&str, &[u8]> =
    TableDefinition::new("auth_issuer_keys_by_project");
/// Cluster fleet membership (HA), one row per `jkbase-server` host instance, keyed
/// by `host_id`. The leader's placement + dead-host detection (P3) read this; at HA
/// P0 it is schema only — CRUD + tests, no loop touches it yet.
const HOSTS: TableDefinition<&str, &[u8]> = TableDefinition::new("hosts");

/// L4 (UDP/TCP) public-port allocations, keyed by the composite `{project_id}:{name}`
/// so one project can hold several named ports (many-per-project like `SECRETS`, unlike
/// the one-per-project `VM_ALLOCATIONS`). Each row reserves one always-on host edge
/// port. See docs/managed-l4-udp-ingress-design.md §3(b).
const PORT_ALLOCATIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("port_allocations");

/// Recently-freed L4 external ports in a reuse-cooldown, keyed by the port (decimal
/// string) → freed-at unix seconds. `allocate_port` skips a port still within the
/// cooldown so a torn-down tenant's stale clients can't have their datagrams admitted
/// into a different tenant that reused the port [threat M1]. Pruned on expiry.
const PORT_QUARANTINE: TableDefinition<&str, &[u8]> = TableDefinition::new("port_quarantine");

/// Subdomain labels reserved for the platform; tenants cannot claim them as new
/// hostnames (existing projects with these ids are grandfathered at backfill).
pub const RESERVED_LABELS: &[&str] = &["api", "www", "console", "storage", "auth"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    Active,
    Stopped,
    Hibernated,
    /// Registered, but its deployable artifacts (content image / hosting content,
    /// and any snapshot) are gone — so it can never wake. Set by the boot reconcile
    /// and the wake gate; cleared by a successful (re)deploy. The proxy serves a
    /// clear "needs redeploy" instead of looping on "starting up".
    #[serde(rename = "needs_redeploy")]
    NeedsRedeploy,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub project_id: String,
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub created_at: u64,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    /// sha256 of the content-addressed base rootfs (`base-rootfs/<hash>.ext4`) the VM was
    /// ACTUALLY running when snapshotted (cold boot = the current hash; a restored VM = the
    /// hash it restored against, NOT the process's current hash). The restore is byte-correct
    /// ONLY against that exact blob; a redeploy that ships a new agent mints a NEW hash/blob
    /// alongside the old, so this pins the restore to the bytes its guest RAM expects. `None`
    /// for legacy records written before content-addressing — the wake path treats those as
    /// non-restorable (fail open to cold boot).
    #[serde(default)]
    pub base_rootfs_hash: Option<String>,
    /// `project.current_version` at hibernate. The metadata image (`content-images/{id}.ext4`,
    /// carrying secrets + routes), the app layer, and the baselayers are ALL rebuilt/repinned
    /// per deploy and snapshot-baked by fixed path — so a single equality check vs the project's
    /// current version gates restore on all of them at once: version drift ⇒ fail open to a cold
    /// boot (which re-injects current secrets) and clears the stale snapshot. `None` = legacy.
    #[serde(default)]
    pub deployment_version: Option<u64>,
    // NB: the two fields above are `#[serde(default)] Option` and the SNAPSHOTS table is encoded
    // with serde_json (self-describing, no `deny_unknown_fields`) — so a legacy record reads back
    // as `None` AND an older binary ignores these unknown keys on rollback. That back/forward
    // compatibility is load-bearing: switching this table to bincode/postcard would silently
    // reintroduce the brick (a trailing Option EOFs on legacy reads).
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Project {
    pub id: String,
    pub name: String,
    pub tenant_id: Option<String>,
    pub current_version: Option<u64>,
    #[serde(default = "default_state")]
    pub state: ProjectState,
    pub vm_ip: Option<String>,
    #[serde(default)]
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VmAllocation {
    pub project_id: String,
    pub ip: String,
    pub tap_device: String,
    pub mac: String,
    /// The cluster host that currently owns/runs this VM (`HostRecord.host_id`).
    /// Empty for single-node allocations and for records written before HA P0; the
    /// leader's placement (P3) populates it. `#[serde(default)]` so pre-HA records
    /// deserialize unchanged.
    #[serde(default)]
    pub host_id: String,
    /// Monotonic placement epoch, bumped each time the leader (re)assigns this VM to
    /// a host. The single-writer safety core (P2): a host self-terminates its
    /// Firecracker before any survivor attaches once its held epoch goes stale. 0 for
    /// single-node / pre-HA records.
    #[serde(default)]
    pub placement_epoch: u64,
}

/// One reserved L4 (UDP/TCP) public port for a project, keyed in `PORT_ALLOCATIONS` by
/// the composite `{project_id}:{name}`. Mirrors [`VmAllocation`] (a control-store-backed,
/// host-island-scoped reservation) but many-per-project.
///
/// The split of who-decides-what is load-bearing [P0-L4-8]: the tenant authors ONLY
/// `proto` + `guest_port` (via `[l4.<name>]`); `external_port` (the public bound port) and
/// `agent_udp_port` (the in-VM transit listen port) are HOST-decided and tenant-unforgeable.
/// `external_port` is **sticky** — stable across redeploy/rollback/VM re-adoption so a
/// flagship tenant's pinned port (and every SRV target) never moves under it.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PortAllocation {
    pub project_id: String,
    /// The `[l4.<name>]` key; the composite `{project_id}:{name}` is the table key so a
    /// project can hold several ports.
    pub name: String,
    /// Transport wire name, `"udp"` | `"tcp"` (from [`jkbase_common::config::L4Proto::as_str`]).
    pub proto: String,
    /// The public host-bound port. Host-asserted and STICKY (see type docs).
    pub external_port: u16,
    /// The loopback port the tenant's service binds inside the guest.
    pub guest_port: u16,
    /// The in-VM transit listen port the host dials (`vm_ip:agent_udp_port`); the agent
    /// land-forwards to `127.0.0.1:guest_port`. Host-set and DISTINCT from `guest_port`.
    pub agent_udp_port: u16,
    /// Admin-granted fixed port (e.g. TeamSpeak's `9987`): never auto-reallocated away,
    /// never drawn for another project. See §3(b) pin-grant.
    #[serde(default)]
    pub pinned: bool,
    /// The cluster host that owns this allocation (`HostRecord.host_id`); empty for
    /// single-node. Ports are allocated per host-island, so the allocator scans by this.
    #[serde(default)]
    pub host_id: String,
    /// Placement epoch, mirrors [`VmAllocation::placement_epoch`]; 0 single-node/pre-HA.
    #[serde(default)]
    pub placement_epoch: u64,
}

/// A host's declared scheduling capacity — the placement bin-packing input (P3).
/// Zero means "unset/auto": a scheduler treats 0 as no declared bound.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct HostCapacity {
    pub vcpus: u32,
    pub mem_mib: u64,
    pub max_vms: u32,
}

/// One cluster host: a `jkbase-server` instance, keyed by `host_id` in `HOSTS`. The
/// fleet's source of truth for placement and failover — the leader reads
/// `last_heartbeat` for dead-host detection and `capacity` for least-loaded-in-region
/// placement (P3), and `cpu_template_id`/`kernel_id` decide warm-vs-cold cross-host
/// restore (P5). Schema only at HA P0: no loop writes or reads these yet.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HostRecord {
    /// Stable, cluster-unique id for this server instance (`--host-id`).
    pub host_id: String,
    /// Placement region; projects are placed least-loaded WITHIN a region.
    pub region: String,
    /// Address peers/the proxy use to forward to this host (deploy forwarding in P3,
    /// routing `Backend.host_addr` in P4). `None` until declared.
    #[serde(default)]
    pub public_addr: Option<String>,
    /// Epoch seconds of this host's last heartbeat; the leader treats a stale value
    /// as a dead host (P3). 0 = never beaten.
    #[serde(default)]
    pub last_heartbeat: u64,
    /// Firecracker CPU template this host bakes into its VMs from first boot; a warm
    /// cross-host snapshot restore (P5) is only safe when source+target match. `None`
    /// = no template pinned (cold-boot only).
    #[serde(default)]
    pub cpu_template_id: Option<String>,
    /// Guest-kernel identity; a warm restore also requires matching kernels (P5).
    #[serde(default)]
    pub kernel_id: Option<String>,
    /// Declared scheduling capacity for placement bin-packing (P3).
    #[serde(default)]
    pub capacity: HostCapacity,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub project_id: String,
    pub key: String,
    pub value: String,
}

/// A tenant S3 access key for the object store. The `secret_key` is stored in
/// cleartext at rest (unlike argon2'd passwords) because SigV4 verification must
/// recompute the HMAC from it; the control db is already the trust root for all
/// tenant state. Bound to `project_id` so a signature resolves to exactly one
/// project's object-store root.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessKey {
    pub access_key_id: String,
    pub project_id: String,
    /// The tenant that minted the key. The object-store auth path re-checks this
    /// against the project's CURRENT owner (like the git-push token), so a key
    /// orphaned by a crash-interrupted teardown can't be inherited by a different
    /// tenant who later recreates the same-slug project. `#[serde(default)]` so a key
    /// written before this field existed deserializes (with empty tenant → fails the
    /// ownership check → safe).
    #[serde(default)]
    pub tenant_id: String,
    pub secret_key: String,
    /// Optional tenant-supplied label (e.g. "ci", "backups"); never authoritative.
    pub label: String,
    pub created_unix: u64,
}

/// An owner-held credential for the managed-DB reach plane — the native-TCP ingress
/// sidecar (or a future TLS-capable `@rhypedb/client`) presents it in the connection
/// preamble. FORKED from the S3 [`AccessKey`] lifecycle but deliberately NOT the same
/// record:
/// - it lives in the separate `DB_ACCESS_KEYS` keyspace with a `JKBD` akid prefix
///   ([R2]) — an S3 `JKBA…` key can't resolve here and a DB key can't sign SigV4;
/// - it stores ONLY `token_fingerprint = sha256(secret)` ([R4]). The 240-bit secret is
///   returned once at mint and never persisted, so a control-db read yields no usable DB
///   credential, and verification is an O(1) lookup + const-time fingerprint compare —
///   no cleartext-at-rest (the SigV4 `secret_key` trap) and no argon2-per-connect (a
///   CPU-DoS amplifier on the attacker-reachable, reconnect-heavy reach endpoint).
///
/// Owner-bound via `tenant_id`, re-checked against the project's current owner on the
/// reach path so a key orphaned by a crash-interrupted teardown can't be inherited.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbAccessKey {
    pub access_key_id: String,
    pub project_id: String,
    /// The tenant that minted the key; re-checked against the project's current owner.
    /// `#[serde(default)]` so an older record deserializes (empty tenant → fails the
    /// ownership re-bind → safe).
    #[serde(default)]
    pub tenant_id: String,
    /// SHA-256 (hex) of the secret. The plaintext is shown once at mint and never stored.
    pub token_fingerprint: String,
    /// Optional owner-supplied label (e.g. "ci", "prod-app"); never authoritative.
    pub label: String,
    pub created_unix: u64,
}

impl DbAccessKey {
    /// Const-time check that `presented_secret` matches this key's stored fingerprint.
    /// The reach-plane edge calls this after an O(1) [`Store::lookup_db_access_key`].
    pub fn verify_secret(&self, presented_secret: &str) -> bool {
        auth::fingerprint_eq(presented_secret, &self.token_fingerprint)
    }
}

/// A jkbase-Auth **issuer key** (P3): the `jkbk_` bearer a tenant's own backend presents to the
/// `auth.` mint endpoint. Like [`DbAccessKey`] it stores ONLY the secret's sha256 fingerprint
/// ([R4]) and is `tenant_id`-bound so the mint path can re-check the project's current owner
/// (P0-AUTH-3) — a key orphaned by a crash-interrupted teardown can't be inherited by a recreated
/// same-slug project. `key_id` is a public, non-secret handle used only for list/revoke.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuerKey {
    pub key_id: String,
    pub project_id: String,
    /// The tenant that minted the key; re-checked against the project's current owner.
    /// `#[serde(default)]` so an older record deserializes (empty tenant → fails the re-bind → safe).
    #[serde(default)]
    pub tenant_id: String,
    /// SHA-256 (hex) of the secret. The plaintext is shown once at mint and never stored.
    pub token_fingerprint: String,
    /// Optional owner-supplied label (e.g. "web-backend"); never authoritative.
    pub label: String,
    pub created_unix: u64,
}

impl IssuerKey {
    /// Const-time check that `presented_secret` matches this key's stored fingerprint.
    pub fn verify_secret(&self, presented_secret: &str) -> bool {
        auth::fingerprint_eq(presented_secret, &self.token_fingerprint)
    }
}

/// One materialized Ed25519 signing key at rest. The `seed_b64` is the 32-byte PRIVATE seed
/// (base64url) — recoverable host-only, exactly like the S3 secret, and NEVER emitted; only
/// `public_b64` is published (JWKS). `kid` is `"{project_id}.{serial}"`. Deliberately NOT `Debug`
/// (P0-AUTH-2): a `tracing::debug!(?state)` would otherwise dump the private seed to logs.
#[derive(Clone, Serialize, Deserialize)]
pub struct StoredSigningKey {
    pub kid: String,
    pub seed_b64: String,
    pub public_b64: String,
    pub created_unix: u64,
}

/// A signing key that has been rotated out but is still inside the overlap window (P0-AUTH-4): its
/// PUBLIC half stays in JWKS until `retire_at` so tokens minted just before the rotation keep
/// verifying. The private seed is dropped at rotation — a retiring key can verify, never sign.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetiringKey {
    pub kid: String,
    pub public_b64: String,
    /// Unix time after which this key drops out of JWKS. Set to `rotation_time + window`, where the
    /// window is ≥ the max token TTL so no live token is stranded.
    pub retire_at: u64,
}

/// Per-project jkbase-Auth signing-key state. Exactly one CURRENT keypair (used to sign) plus the
/// set of `retiring` public keys still inside their retirement windows (P0-AUTH-4) — a Vec, not a
/// single slot, so BACK-TO-BACK soft rotations don't strand tokens minted under a key whose window
/// hasn't closed. `next_serial` monotonically numbers kids so a recreated key never reuses a retired
/// kid. Not `Debug` because it embeds the private-seed-bearing [`StoredSigningKey`] (P0-AUTH-2).
#[derive(Clone, Serialize, Deserialize)]
pub struct SigningKeyState {
    pub current: StoredSigningKey,
    /// Rotated-out public keys still within their `retire_at` windows (pruned on read/rotate;
    /// cleared on a HARD rotation). Bounded by [`Store::MAX_RETIRING_SIGNING_KEYS`].
    #[serde(default)]
    pub retiring: Vec<RetiringKey>,
    pub next_serial: u64,
}

/// Lifecycle of a managed-DB backup ([RB8]). A backup is a two-phase operation: the row is
/// written `Pending`, the tar is pulled + stored + its end-of-archive marker validated, and
/// only then is the row flipped to `Complete`. A truncated/failed stream lands `Failed`
/// (its partial object deleted). Restore refuses any non-`Complete` backup.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BackupStatus {
    Pending,
    Complete,
    Failed,
}

/// One catalog entry for a managed-DB backup. Metadata only — the tar itself lives in the
/// platform object store at [`Self::object_key`], NEVER in redb. The `object_key` is
/// server-authored (derived from `project_id` + `backup_id`); restore resolves an opaque
/// `backup_id` through the per-project index to this key, so a caller can never point restore
/// at an arbitrary storage path ([RB6]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbBackup {
    pub backup_id: String,
    pub project_id: String,
    /// The tenant that owned the project when the backup was taken; re-checked against the
    /// project's current owner on restore (an orphaned backup can't be inherited). Empty on
    /// an older record → fails the re-bind → safe.
    #[serde(default)]
    pub tenant_id: String,
    pub created_at_ms: u64,
    /// Size of the stored tar, filled in when the backup completes (0 while `Pending`).
    #[serde(default)]
    pub size_bytes: u64,
    /// Key in the platform `db-backups` object store (server-authored, not caller-supplied).
    pub object_key: String,
    /// Short human summary from the tar `MANIFEST.json` (e.g. sst count / max_version); best
    /// effort, empty until complete.
    #[serde(default)]
    pub manifest_summary: String,
    pub status: BackupStatus,
}

/// Per-project connected-repo build-trigger credentials (build · D). Stored
/// once per project in the `REPO_TRIGGERS` table. Absent until the tenant mints
/// a git-push token via `jkbase repo connect`.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct RepoTriggerConfig {
    pub project_id: String,
    /// The tenant that minted the token. Authentication re-checks this against
    /// the project's *current* owner, so a record that outlives a delete/recreate
    /// of the same project slug can't authenticate a different tenant's push.
    #[serde(default)]
    pub tenant_id: Option<String>,
    /// SHA-256 (hex) of the per-project git-push token, or `None` if not minted.
    /// The plaintext token is shown once at mint time and never stored.
    pub git_token_fingerprint: Option<String>,
    pub git_token_created_at: u64,
}

/// Metadata for one immutable deployment of a project. The artifacts live on
/// disk at `{deploy_dir}/{project_id}/deployments/v{version}`; this records the
/// version history so the platform can list past deploys and roll back to one.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeploymentMeta {
    pub project_id: String,
    pub version: u64,
    pub created_at: u64,
    /// Content-addressed layer digests this version deploys (base + app). Used to
    /// roll back to the exact layer set without rebuilding, and to refcount the
    /// shared base-store on prune so a blob a retained version still references is
    /// never GC'd. Empty for legacy (flat) deployments.
    #[serde(default)]
    pub layer_digests: Vec<String>,
}

/// Lifecycle phase of a build job, or of one of its per-target sub-builds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum BuildPhase {
    /// Accepted, not yet started.
    Queued,
    /// Source unpacked; per-target build VMs running (or assembling).
    Building,
    /// All targets built and the artifacts activated via the deploy tail.
    Succeeded,
    /// A target failed, timed out, or crashed — the whole build failed (atomic).
    Failed,
}

/// Which kind of deploy target a sub-build produces.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TargetKind {
    Function,
    Server,
    /// A static build target: the build VM runs a buildpack that produces a static
    /// tree (e.g. `trunk build` → `dist/`), and the host serves that tree as site
    /// content via `[hosting]`/`[sites]` — no runnable server process. The build
    /// output is a plain `static.tar.gz` the host untars into the staged site
    /// location, NOT a server manifest or a wasm function.
    Static,
}

/// Per-target status within a build job. One build VM fans out per target
/// (design §12); this records that VM's progress and outcome.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildTargetStatus {
    pub name: String,
    pub kind: TargetKind,
    pub phase: BuildPhase,
    /// Human-readable detail: the build VM outcome, exit code, or failure reason.
    #[serde(default)]
    pub detail: Option<String>,
    #[serde(default)]
    pub cache_hit: bool,
    #[serde(default)]
    pub started_at: Option<u64>,
    #[serde(default)]
    pub finished_at: Option<u64>,
    /// `sha256:…` of the toolchain image this target built with (provenance).
    #[serde(default)]
    pub builder_digest: Option<String>,
    /// Platform-computed cache key (toolchain + lockfile + source digests).
    #[serde(default)]
    pub cache_key: Option<String>,
    /// Resolved source commit when the build came via git-push; else `None`.
    #[serde(default)]
    pub source_commit: Option<String>,
    /// Per-phase wall-clock timings reported by the in-VM lifecycle
    /// (`detect`/`fetch`/`compile`/`export`), in milliseconds.
    #[serde(default)]
    pub duration_breakdown_ms: std::collections::BTreeMap<String, u64>,
}

/// One server-side build job: the `POST /build` intake fans out per-target build
/// VMs, collects artifacts, and (on success) hands them to the deploy tail. The
/// record is persisted independent of `log_shipper` so `GET /builds/{id}` can
/// surface terminal status, per-target sub-status, the captured log tail, and
/// per-phase timings. `build_id` is a per-project monotonic sequence; the on-disk
/// key zero-pads it so builds sort by recency within a project.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BuildRecord {
    pub project_id: String,
    pub build_id: u64,
    pub phase: BuildPhase,
    #[serde(default)]
    pub targets: Vec<BuildTargetStatus>,
    /// Captured tail of the combined build log.
    #[serde(default)]
    pub log_tail: String,
    /// Per-phase wall-clock timings (e.g. `fanout`, `activate`) in milliseconds.
    #[serde(default)]
    pub phase_timings_ms: std::collections::BTreeMap<String, u64>,
    /// Set once a successful build activates a deployment.
    #[serde(default)]
    pub deployed_version: Option<u64>,
    /// Set on failure: the terminal error summary.
    #[serde(default)]
    pub error: Option<String>,
    /// Resolved source commit when the build came via git-push; else `None`.
    #[serde(default)]
    pub source_commit: Option<String>,
    pub created_at: u64,
    pub updated_at: u64,
}

/// A registered cron schedule for one WASM function. The host scheduler reads
/// these as the single source of truth and fires due functions, advancing
/// `last_run` after each successful invocation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ScheduleRecord {
    pub project_id: String,
    pub function: String,
    /// 5-field UNIX cron, e.g. "*/5 * * * *".
    pub cron: String,
    /// Epoch secs of the last fired occurrence; `None` = never run.
    pub last_run: Option<u64>,
}

/// One hour's metered usage for a project. Counters accumulate across samples
/// within the hour; storage is a gauge so we keep both its time-integral
/// (`storage_byte_seconds`, for GB-hour billing) and the latest reading.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct UsageBucket {
    pub project_id: String,
    /// Epoch seconds floored to the hour: `(now / 3600) * 3600`.
    pub hour_epoch: u64,
    /// CPU jiffies (USER_HZ=100); convert to seconds (/100.0) only at display.
    pub cpu_jiffies: u64,
    /// TAP rx bytes = guest egress.
    pub rx_bytes: u64,
    /// TAP tx bytes = guest ingress.
    pub tx_bytes: u64,
    /// Time-integral of the storage gauge (bytes * seconds) for the hour.
    pub storage_byte_seconds: u64,
    /// Latest sampled storage gauge (bytes).
    pub storage_bytes_last: u64,
    pub sample_count: u32,
    /// Build-VM seconds billed this hour, metered on build exit (not the 60 s
    /// sampler tick). Distinct from `cpu_jiffies` (runtime-VM CPU).
    #[serde(default)]
    pub build_seconds: u64,
    /// Seconds this hour the runtime VM was held warm by a managed-DB reach-plane
    /// relay (`Running` while `conn_count > 0`) — DB-attributable warm-time, so an
    /// idle external DB connection that pins a VM warm is billed, not free.
    /// `#[serde(default)]` for back-compat with pre-warm-metering buckets.
    #[serde(default)]
    pub warm_seconds: u64,
}

/// A per-project override of the L4 egress ceilings, for a workload the platform defaults were
/// not sized for — the motivating case is a conferencing SFU, whose *egress* leg carries
/// `participants x (participants - 1)` media streams and meets `per_source_bps` long before
/// anything else.
///
/// Every field is optional and layered over the platform default individually: a partial override
/// must not silently zero a field it didn't mention, because a zero-rate bucket admits nothing and
/// the failure would look like total packet loss rather than a config error.
///
/// **This cannot widen what a THIRD PARTY receives.** Every reply still passes the platform victim
/// backstop (`L4PlaneLimits::per_victim_bps`) after these, so raising a project's numbers alone
/// changes only how that project's own budget is divided. Moving the third-party bound is a
/// separate, deliberate platform-operator action.
///
/// Platform-admin-set only (`X-Admin-Token`), for the obvious reason: a tenant able to write its
/// own limits would write infinity.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct L4EgressLimits {
    /// Egress toward any ONE destination IP, per port (bytes/sec).
    #[serde(default)]
    pub per_source_bps: Option<u64>,
    /// Burst for the above (bytes).
    #[serde(default)]
    pub per_source_burst: Option<u64>,
    /// The project's total L4 egress across all its ports (bytes/sec).
    #[serde(default)]
    pub per_project_bps: Option<u64>,
}

/// Per-project resource limits. Absent override -> [`DEFAULT_QUOTA`].
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct QuotaLimits {
    pub storage_bytes_max: u64,
    pub bandwidth_bytes_per_month: u64,
    /// Server-side build-VM seconds per UTC month. `#[serde(default)]` so quota
    /// overrides stored before build metering existed still deserialize.
    #[serde(default = "default_build_seconds_per_month")]
    pub build_seconds_per_month: u64,
    /// Maximum number of objects (files) across all buckets for this project.
    /// `#[serde(default)]` so overrides stored before this field existed still
    /// deserialize with the platform default.
    #[serde(default = "default_max_objects")]
    pub max_objects: u64,
    /// Maximum number of buckets for this project.
    #[serde(default = "default_max_buckets")]
    pub max_buckets: u64,
}

const DEFAULT_BUILD_SECONDS_PER_MONTH: u64 = 200 * 60; // 200 build-minutes/month
fn default_build_seconds_per_month() -> u64 {
    DEFAULT_BUILD_SECONDS_PER_MONTH
}

const DEFAULT_MAX_OBJECTS: u64 = 1_000_000;
fn default_max_objects() -> u64 {
    DEFAULT_MAX_OBJECTS
}

const DEFAULT_MAX_BUCKETS: u64 = 100;
fn default_max_buckets() -> u64 {
    DEFAULT_MAX_BUCKETS
}

pub const DEFAULT_QUOTA: QuotaLimits = QuotaLimits {
    storage_bytes_max: 16 * 1024 * 1024 * 1024, // 16 GiB
    bandwidth_bytes_per_month: 100 * 1024 * 1024 * 1024, // 100 GiB/month
    build_seconds_per_month: DEFAULT_BUILD_SECONDS_PER_MONTH,
    max_objects: DEFAULT_MAX_OBJECTS,
    max_buckets: DEFAULT_MAX_BUCKETS,
};

/// Enforcement state for a project. Source of truth for the wake gate, so a
/// racing wake is refused even mid-hibernate. Written before hibernation.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QuotaStatus {
    pub project_id: String,
    pub bandwidth_blocked: bool,
    pub blocked_reason: Option<String>,
    /// Epoch secs the block was set.
    pub blocked_at: u64,
    /// `month_start_epoch` that triggered the block; used to clear on rollover.
    pub blocked_month: u64,
}

/// Summed month-to-date usage. Storage is the latest gauge, not summed.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize)]
pub struct MonthToDate {
    pub cpu_jiffies: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
    pub storage_bytes: u64,
    pub build_seconds: u64,
    #[serde(default)]
    pub warm_seconds: u64,
}

/// Per-tenant resource limits. Absent override -> [`DEFAULT_TENANT_QUOTA`]. The
/// platform's first tenant-scoped quota (every other quota is per-project).
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct TenantQuotaLimits {
    /// Max number of the tenant's projects that may be held warm SIMULTANEOUSLY by
    /// managed-DB reach-plane relays (external DB connections). Bounds a tenant's
    /// host footprint so one idle DB connection per project can't pin every VM
    /// warm. The in-VM app->DB loopback path is unaffected (it never registers a
    /// relay). `#[serde(default)]` so overrides stored before this field existed
    /// still deserialize with the platform default.
    #[serde(default = "default_warm_vm_max")]
    pub warm_vm_max: u32,
    /// Max TOTAL live managed-DB relays the tenant may hold across ALL its projects.
    /// `warm_vm_max` bounds distinct warm *projects*, but each may hold up to the
    /// per-project relay cap, so `warm_vm_max * per_project` relays could fill the
    /// global pool and starve other tenants; this bounds the tenant's total slice of
    /// it directly. `#[serde(default)]` for pre-existing overrides. Raise this together
    /// with `warm_vm_max` when granting a bigger tenant more warm projects.
    #[serde(default = "default_warm_relay_max")]
    pub warm_relay_max: u32,
}

const DEFAULT_WARM_VM_MAX: u32 = 16;
fn default_warm_vm_max() -> u32 {
    DEFAULT_WARM_VM_MAX
}

/// Default per-tenant relay cap: a quarter of the edge's 1024-relay global pool, so at
/// least four tenants can be maxed at once, with ample headroom over `warm_vm_max` (16)
/// warm projects (~16 relays/project). Conceptually paired with the edge caps in
/// `jkbase-server`'s `ProxyConfig` (`db_max_concurrent` / `db_max_per_project`).
const DEFAULT_WARM_RELAY_MAX: u32 = 256;
fn default_warm_relay_max() -> u32 {
    DEFAULT_WARM_RELAY_MAX
}

pub const DEFAULT_TENANT_QUOTA: TenantQuotaLimits = TenantQuotaLimits {
    warm_vm_max: DEFAULT_WARM_VM_MAX,
    warm_relay_max: DEFAULT_WARM_RELAY_MAX,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainKind {
    /// `<label>.jkbase.app` — platform-owned, covered by the wildcard cert.
    Subdomain,
    /// An external domain (e.g. `docs.example.com`) the tenant must prove they own.
    Custom,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DomainStatus {
    /// Claimed but not yet routable (custom domains await DNS-TXT verification).
    Pending,
    /// Verified/owned and eligible for routing.
    Active,
}

/// A claimed hostname. The registry of these is the single source of truth for
/// routing — global uniqueness is enforced on `host` (the routing key: a bare
/// label for [`DomainKind::Subdomain`], the full host for [`DomainKind::Custom`]).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DomainRecord {
    pub host: String,
    pub project_id: String,
    pub tenant_id: String,
    /// Which site within the project this host serves; `None` = the default site.
    pub site: Option<String>,
    pub kind: DomainKind,
    pub status: DomainStatus,
    /// DNS-TXT verification token (relevant for custom domains).
    pub token: String,
    pub created_at: u64,
}

/// Whether `host` is a reserved platform label.
pub fn host_is_reserved(host: &str) -> bool {
    RESERVED_LABELS.contains(&host)
}

fn default_state() -> ProjectState {
    ProjectState::Stopped
}

/// Epoch seconds of the start (00:00:00) of the UTC calendar month containing
/// `now`. The single month-boundary convention used by metering, enforcement,
/// and the usage API — all UTC, so rollover is deterministic and host-TZ-free.
pub fn month_start_epoch(now: u64) -> u64 {
    use chrono::{Datelike, TimeZone, Utc};
    let dt = match Utc.timestamp_opt(now as i64, 0).single() {
        Some(dt) => dt,
        None => return 0,
    };
    Utc.with_ymd_and_hms(dt.year(), dt.month(), 1, 0, 0, 0)
        .single()
        .map(|d| d.timestamp() as u64)
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path).context("failed to open database")?;

        let txn = db.begin_write()?;
        let _ = txn.open_table(PROJECTS)?;
        let _ = txn.open_table(VM_ALLOCATIONS)?;
        let _ = txn.open_table(TENANTS)?;
        let _ = txn.open_table(API_TOKENS)?;
        let _ = txn.open_table(SECRETS)?;
        let _ = txn.open_table(SNAPSHOTS)?;
        let _ = txn.open_table(DEPLOYMENTS)?;
        let _ = txn.open_table(BUILDS)?;
        let _ = txn.open_table(DOMAINS)?;
        let _ = txn.open_table(SCHEDULES)?;
        let _ = txn.open_table(USAGE)?;
        let _ = txn.open_table(QUOTAS)?;
        let _ = txn.open_table(QUOTA_STATUS)?;
        let _ = txn.open_table(TENANT_QUOTAS)?;
        let _ = txn.open_table(ACCESS_KEYS)?;
        let _ = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
        let _ = txn.open_table(DB_ACCESS_KEYS)?;
        let _ = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
        let _ = txn.open_table(DB_SPLICE)?;
        let _ = txn.open_table(DB_ADMIN_TOKEN)?;
        let _ = txn.open_table(DB_BACKUPS)?;
        let _ = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
        let _ = txn.open_table(AUTH_SIGNING_KEYS)?;
        let _ = txn.open_table(AUTH_ISSUER_KEYS)?;
        let _ = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
        let _ = txn.open_table(HOSTS)?;
        let _ = txn.open_table(PORT_ALLOCATIONS)?;
        let _ = txn.open_table(PORT_QUARANTINE)?;
        let _ = txn.open_table(L4_TRANSIT)?;
        txn.commit()?;

        Ok(Store { db: Arc::new(db) })
    }

    pub fn create_project(&self, project: &Project) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PROJECTS)?;
            let data = serde_json::to_vec(project)?;
            table.insert(project.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_project(&self, id: &str) -> Result<Option<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        match table.get(id)? {
            Some(data) => {
                let project: Project = serde_json::from_slice(data.value())?;
                Ok(Some(project))
            }
            None => Ok(None),
        }
    }

    pub fn update_project(&self, project: &Project) -> Result<()> {
        self.create_project(project)
    }

    pub fn list_projects(&self) -> Result<Vec<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        let mut projects = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let project: Project = serde_json::from_slice(value.value())?;
            projects.push(project);
        }
        Ok(projects)
    }

    pub fn delete_project(&self, id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(PROJECTS)?;
            table.remove(id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn save_vm_allocation(&self, alloc: &VmAllocation) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(VM_ALLOCATIONS)?;
            let data = serde_json::to_vec(alloc)?;
            table.insert(alloc.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_vm_allocation(&self, project_id: &str) -> Result<Option<VmAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VM_ALLOCATIONS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_vm_allocations(&self) -> Result<Vec<VmAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(VM_ALLOCATIONS)?;
        let mut allocs = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let alloc: VmAllocation = serde_json::from_slice(value.value())?;
            allocs.push(alloc);
        }
        Ok(allocs)
    }

    pub fn remove_vm_allocation(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(VM_ALLOCATIONS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- L4 (UDP/TCP) public-port allocations --

    /// Hard cap on the number of L4 public ports a single project may hold. Bounds
    /// public-port exhaustion, the always-on edge-socket count, AND the wake axis (the
    /// wake budget keys on base-project, so ports can't multiply a tenant's share). See
    /// docs/managed-l4-udp-ingress-design.md §6. Enforced in `allocate_port` under a write
    /// txn (like [`Self::MAX_ACCESS_KEYS_PER_PROJECT`]).
    pub const MAX_L4_PORTS_PER_PROJECT: usize = 5;

    /// Upsert an L4 port allocation, keyed by the composite `{project_id}:{name}`.
    pub fn save_port_allocation(&self, alloc: &PortAllocation) -> Result<()> {
        let key = format!("{}:{}", alloc.project_id, alloc.name);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PORT_ALLOCATIONS)?;
            let data = serde_json::to_vec(alloc)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_port_allocation(
        &self,
        project_id: &str,
        name: &str,
    ) -> Result<Option<PortAllocation>> {
        let key = format!("{project_id}:{name}");
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PORT_ALLOCATIONS)?;
        match table.get(key.as_str())? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// All L4 allocations across every project — the host-island scan input for
    /// `allocate_port` (which filters by `host_id`) and for reconcile.
    pub fn list_port_allocations(&self) -> Result<Vec<PortAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PORT_ALLOCATIONS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_k, v) = entry?;
            out.push(serde_json::from_slice::<PortAllocation>(v.value())?);
        }
        Ok(out)
    }

    /// A single project's L4 allocations (CLI `l4 ls`, redeploy reconcile). Half-open
    /// range over the composite key so `forumall` never matches `forumall2:*`.
    pub fn list_port_allocations_for_project(
        &self,
        project_id: &str,
    ) -> Result<Vec<PortAllocation>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PORT_ALLOCATIONS)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let mut out = Vec::new();
        for entry in table.range(lo.as_str()..hi.as_str())? {
            let (_k, v) = entry?;
            out.push(serde_json::from_slice::<PortAllocation>(v.value())?);
        }
        Ok(out)
    }

    pub fn remove_port_allocation(&self, project_id: &str, name: &str) -> Result<bool> {
        let key = format!("{project_id}:{name}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(PORT_ALLOCATIONS)?;
            table.remove(key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Remove ALL of a project's L4 allocations (project teardown). The `:` separator
    /// makes the prefix exact — `forumall` never matches `forumall2:*`. Returns the count
    /// removed. Without this a recreated project of the same slug could inherit a prior
    /// tenant's ports.
    pub fn remove_all_port_allocations(&self, project_id: &str) -> Result<usize> {
        let prefix = format!("{project_id}:");
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = txn.open_table(PORT_ALLOCATIONS)?;
            // Collect first: redb forbids mutating a table while its iterator is live.
            let keys: Vec<String> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value().to_string())
                .filter(|k| k.starts_with(&prefix))
                .collect();
            for k in keys {
                if table.remove(k.as_str())?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- L4 external-port reuse quarantine [threat M1] --

    /// Record a freed external port entering the reuse-cooldown at `freed_at_unix`.
    /// `allocate_port` skips a port whose cooldown has not elapsed so a torn-down
    /// tenant's stale clients can't be admitted into a reused port's new owner.
    pub fn quarantine_port(&self, port: u16, freed_at_unix: u64) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(PORT_QUARANTINE)?;
            let data = serde_json::to_vec(&freed_at_unix)?;
            table.insert(port.to_string().as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The freed-at time of a quarantined port, or `None` if it isn't quarantined.
    pub fn get_port_quarantine(&self, port: u16) -> Result<Option<u64>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PORT_QUARANTINE)?;
        match table.get(port.to_string().as_str())? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// Drop a port from quarantine (cooldown elapsed / explicit reclaim).
    pub fn unquarantine_port(&self, port: u16) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(PORT_QUARANTINE)?;
            table.remove(port.to_string().as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// All quarantined ports → freed-at unix. `allocate_port` consults this to skip
    /// still-cooling ports and to prune elapsed ones.
    pub fn list_port_quarantine(&self) -> Result<Vec<(u16, u64)>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PORT_QUARANTINE)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            if let Ok(port) = k.value().parse::<u16>() {
                out.push((port, serde_json::from_slice::<u64>(v.value())?));
            }
        }
        Ok(out)
    }

    // -- L4 transit secret (host<->guest per-datagram auth) --

    /// The project's L4 transit secret, minting + persisting a fresh one on first use.
    /// **Sticky**: reused across redeploys so the host relay's copy and the agent's baked
    /// `_l4.json` copy always agree; distinct from the DB splice secret (L4 isn't DB-coupled).
    /// Called at deploy with the returned value baked into `_l4.json`.
    pub fn l4_transit_secret(&self, project_id: &str) -> Result<String> {
        if let Some(s) = self.get_l4_transit_secret(project_id)? {
            return Ok(s);
        }
        let secret = auth::generate_l4_transit_secret();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(L4_TRANSIT)?;
            table.insert(project_id, secret.as_bytes())?;
        }
        txn.commit()?;
        Ok(secret)
    }

    /// The project's L4 transit secret, or `None` if none has been minted. The host relay
    /// reads this to seal/open transit datagrams; a `None` (or a mismatch with the agent's
    /// baked copy) makes the transit auth fail closed.
    pub fn get_l4_transit_secret(&self, project_id: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(L4_TRANSIT)?;
        match table.get(project_id)? {
            Some(v) => Ok(Some(String::from_utf8_lossy(v.value()).into_owned())),
            None => Ok(None),
        }
    }

    /// Drop a project's L4 transit secret (teardown), so a recreated same-slug project
    /// can't inherit it.
    pub fn delete_l4_transit_secret(&self, project_id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(L4_TRANSIT)?;
            table.remove(project_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // -- Hosts (HA cluster fleet; schema only at P0) --

    pub fn save_host(&self, host: &HostRecord) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(HOSTS)?;
            let data = serde_json::to_vec(host)?;
            table.insert(host.host_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_host(&self, host_id: &str) -> Result<Option<HostRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HOSTS)?;
        match table.get(host_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_hosts(&self) -> Result<Vec<HostRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(HOSTS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_k, v) = entry?;
            out.push(serde_json::from_slice::<HostRecord>(v.value())?);
        }
        Ok(out)
    }

    pub fn remove_host(&self, host_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(HOSTS)?;
            table.remove(host_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Read-modify-write just `last_heartbeat` (the P3 heartbeat loop's hot path);
    /// preserves every other field. No-op if the host was removed concurrently.
    pub fn touch_host_heartbeat(&self, host_id: &str, ts: u64) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(HOSTS)?;
            // Own the bytes so the read guard's borrow ends before the insert.
            let existing = table.get(host_id)?.map(|d| d.value().to_vec());
            if let Some(bytes) = existing {
                let mut rec: HostRecord = serde_json::from_slice(&bytes)?;
                rec.last_heartbeat = ts;
                let out = serde_json::to_vec(&rec)?;
                table.insert(host_id, out.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    // -- Snapshots --

    pub fn save_snapshot_meta(&self, meta: &SnapshotMeta) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SNAPSHOTS)?;
            let data = serde_json::to_vec(meta)?;
            table.insert(meta.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_snapshot_meta(&self, project_id: &str) -> Result<Option<SnapshotMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SNAPSHOTS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// Every snapshot record, across all projects. Used by the startup CAS-rootfs GC to
    /// build the set of base-rootfs blobs still referenced by a restorable snapshot, so it
    /// never reaps a blob a hibernated project needs to wake.
    pub fn list_snapshot_metas(&self) -> Result<Vec<SnapshotMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SNAPSHOTS)?;
        let mut metas = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let meta: SnapshotMeta = serde_json::from_slice(value.value())?;
            metas.push(meta);
        }
        Ok(metas)
    }

    pub fn remove_snapshot_meta(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(SNAPSHOTS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Deployments --

    // Zero-padded so the compound key sorts by version within a project.
    fn deployment_key(project_id: &str, version: u64) -> String {
        format!("{project_id}:{version:020}")
    }

    pub fn save_deployment(&self, meta: &DeploymentMeta) -> Result<()> {
        let key = Self::deployment_key(&meta.project_id, meta.version);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DEPLOYMENTS)?;
            let data = serde_json::to_vec(meta)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_deployment(&self, project_id: &str, version: u64) -> Result<Option<DeploymentMeta>> {
        let key = Self::deployment_key(project_id, version);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DEPLOYMENTS)?;
        match table.get(key.as_str())? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// All deployments for a project, newest version first.
    pub fn list_deployments(&self, project_id: &str) -> Result<Vec<DeploymentMeta>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DEPLOYMENTS)?;
        let prefix = format!("{project_id}:");
        let mut deployments = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value().starts_with(&prefix) {
                deployments.push(serde_json::from_slice::<DeploymentMeta>(value.value())?);
            }
        }
        deployments.sort_by_key(|d| std::cmp::Reverse(d.version));
        Ok(deployments)
    }

    pub fn remove_deployment(&self, project_id: &str, version: u64) -> Result<bool> {
        let key = Self::deployment_key(project_id, version);
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(DEPLOYMENTS)?;
            table.remove(key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Builds --

    // Zero-padded so the compound key sorts by build_id within a project.
    fn build_key(project_id: &str, build_id: u64) -> String {
        format!("{project_id}:{build_id:020}")
    }

    /// The next build id for a project: one past the highest existing id. Safe
    /// because `POST /build` serializes per project via the deploy lock.
    pub fn next_build_id(&self, project_id: &str) -> Result<u64> {
        Ok(self
            .list_builds(project_id)?
            .first()
            .map(|b| b.build_id)
            .unwrap_or(0)
            + 1)
    }

    pub fn save_build(&self, rec: &BuildRecord) -> Result<()> {
        let key = Self::build_key(&rec.project_id, rec.build_id);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(BUILDS)?;
            let data = serde_json::to_vec(rec)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_build(&self, project_id: &str, build_id: u64) -> Result<Option<BuildRecord>> {
        let key = Self::build_key(project_id, build_id);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUILDS)?;
        match table.get(key.as_str())? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// All build jobs for a project, newest build_id first.
    pub fn list_builds(&self, project_id: &str) -> Result<Vec<BuildRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(BUILDS)?;
        let prefix = format!("{project_id}:");
        let mut builds = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value().starts_with(&prefix) {
                builds.push(serde_json::from_slice::<BuildRecord>(value.value())?);
            }
        }
        builds.sort_by_key(|b| std::cmp::Reverse(b.build_id));
        Ok(builds)
    }

    pub fn remove_build(&self, project_id: &str, build_id: u64) -> Result<bool> {
        let key = Self::build_key(project_id, build_id);
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(BUILDS)?;
            table.remove(key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Keep only the `keep` most recent build records for a project (history
    /// bound; artifacts already live under the deployment, not the build job).
    pub fn prune_builds(&self, project_id: &str, keep: usize) -> Result<()> {
        let builds = self.list_builds(project_id)?;
        for old in builds.into_iter().skip(keep) {
            let _ = self.remove_build(project_id, old.build_id);
        }
        Ok(())
    }

    // -- Schedules --

    fn schedule_key(project_id: &str, function: &str) -> String {
        format!("{project_id}:{function}")
    }

    pub fn save_schedule(&self, rec: &ScheduleRecord) -> Result<()> {
        let key = Self::schedule_key(&rec.project_id, &rec.function);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCHEDULES)?;
            let data = serde_json::to_vec(rec)?;
            table.insert(key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Every schedule across all projects (the scheduler loop reads this each tick).
    pub fn list_schedules(&self) -> Result<Vec<ScheduleRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCHEDULES)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_k, v) = entry?;
            out.push(serde_json::from_slice::<ScheduleRecord>(v.value())?);
        }
        Ok(out)
    }

    pub fn list_schedules_for_project(&self, project_id: &str) -> Result<Vec<ScheduleRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SCHEDULES)?;
        let prefix = format!("{project_id}:");
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&prefix) {
                out.push(serde_json::from_slice::<ScheduleRecord>(v.value())?);
            }
        }
        Ok(out)
    }

    pub fn remove_schedule(&self, project_id: &str, function: &str) -> Result<bool> {
        let key = Self::schedule_key(project_id, function);
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(SCHEDULES)?;
            table.remove(key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Read-modify-write just `last_run`. No-op if the schedule was removed
    /// concurrently (e.g. an undeploy raced the fire).
    pub fn update_schedule_last_run(
        &self,
        project_id: &str,
        function: &str,
        ts: u64,
    ) -> Result<()> {
        let key = Self::schedule_key(project_id, function);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SCHEDULES)?;
            // Copy out to an owned buffer so the read AccessGuard borrow ends
            // before we take the mutable borrow for insert.
            let existing = table.get(key.as_str())?.map(|d| d.value().to_vec());
            if let Some(bytes) = existing {
                let mut rec: ScheduleRecord = serde_json::from_slice(&bytes)?;
                rec.last_run = Some(ts);
                let out = serde_json::to_vec(&rec)?;
                table.insert(key.as_str(), out.as_slice())?;
            }
        }
        txn.commit()?;
        Ok(())
    }

    // -- Usage (metering rollups) --

    fn usage_key(project_id: &str, hour_epoch: u64) -> String {
        format!("{project_id}:{hour_epoch:020}")
    }

    /// Accumulate one sample's deltas into the project's current hour bucket.
    #[allow(clippy::too_many_arguments)] // one flat sample row; a struct adds no clarity here
    pub fn add_usage(
        &self,
        project_id: &str,
        hour_epoch: u64,
        cpu_jiffies: u64,
        rx_bytes: u64,
        tx_bytes: u64,
        storage_bytes_sample: u64,
        elapsed_secs: u64,
    ) -> Result<()> {
        let key = Self::usage_key(project_id, hour_epoch);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(USAGE)?;
            let existing = table.get(key.as_str())?.map(|d| d.value().to_vec());
            let mut bucket: UsageBucket = match existing {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => UsageBucket {
                    project_id: project_id.to_string(),
                    hour_epoch,
                    ..Default::default()
                },
            };
            bucket.cpu_jiffies = bucket.cpu_jiffies.saturating_add(cpu_jiffies);
            bucket.rx_bytes = bucket.rx_bytes.saturating_add(rx_bytes);
            bucket.tx_bytes = bucket.tx_bytes.saturating_add(tx_bytes);
            bucket.storage_byte_seconds = bucket
                .storage_byte_seconds
                .saturating_add(storage_bytes_sample.saturating_mul(elapsed_secs));
            bucket.storage_bytes_last = storage_bytes_sample;
            bucket.sample_count += 1;
            let out = serde_json::to_vec(&bucket)?;
            table.insert(key.as_str(), out.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Add `build_seconds` to a project's hourly bucket. Metered on build-VM exit
    /// (we own the lifecycle), so a build killed between 60 s sampler ticks is
    /// still billed — closing the free-compute window (threat-model P1-4).
    pub fn add_build_usage(
        &self,
        project_id: &str,
        hour_epoch: u64,
        build_seconds: u64,
    ) -> Result<()> {
        let key = Self::usage_key(project_id, hour_epoch);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(USAGE)?;
            let existing = table.get(key.as_str())?.map(|d| d.value().to_vec());
            let mut bucket: UsageBucket = match existing {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => UsageBucket {
                    project_id: project_id.to_string(),
                    hour_epoch,
                    ..Default::default()
                },
            };
            bucket.build_seconds = bucket.build_seconds.saturating_add(build_seconds);
            let out = serde_json::to_vec(&bucket)?;
            table.insert(key.as_str(), out.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Add `warm_seconds` (DB-attributable warm-time) to a project's hourly bucket.
    /// Accrued by the metering loop for a `Running` VM held warm by a managed-DB
    /// relay (`conn_count > 0`), so an idle external DB connection is billed.
    pub fn add_warm_usage(
        &self,
        project_id: &str,
        hour_epoch: u64,
        warm_seconds: u64,
    ) -> Result<()> {
        let key = Self::usage_key(project_id, hour_epoch);
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(USAGE)?;
            let existing = table.get(key.as_str())?.map(|d| d.value().to_vec());
            let mut bucket: UsageBucket = match existing {
                Some(bytes) => serde_json::from_slice(&bytes)?,
                None => UsageBucket {
                    project_id: project_id.to_string(),
                    hour_epoch,
                    ..Default::default()
                },
            };
            bucket.warm_seconds = bucket.warm_seconds.saturating_add(warm_seconds);
            let out = serde_json::to_vec(&bucket)?;
            table.insert(key.as_str(), out.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// All buckets for a project with `hour_epoch` in `[from_hour, to_hour]`, oldest first.
    pub fn list_usage_for_project(
        &self,
        project_id: &str,
        from_hour: u64,
        to_hour: u64,
    ) -> Result<Vec<UsageBucket>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(USAGE)?;
        let prefix = format!("{project_id}:");
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&prefix) {
                let b: UsageBucket = serde_json::from_slice(v.value())?;
                if b.hour_epoch >= from_hour && b.hour_epoch <= to_hour {
                    out.push(b);
                }
            }
        }
        out.sort_by_key(|b| b.hour_epoch);
        Ok(out)
    }

    /// Sum of all buckets at/after `month_start_epoch`. Storage is the latest
    /// gauge (newest bucket), not summed.
    pub fn sum_month_to_date(
        &self,
        project_id: &str,
        month_start_epoch: u64,
    ) -> Result<MonthToDate> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(USAGE)?;
        let prefix = format!("{project_id}:");
        let mut mtd = MonthToDate::default();
        let mut newest_hour = 0u64;
        for entry in table.iter()? {
            let (k, v) = entry?;
            if k.value().starts_with(&prefix) {
                let b: UsageBucket = serde_json::from_slice(v.value())?;
                if b.hour_epoch >= month_start_epoch {
                    mtd.cpu_jiffies = mtd.cpu_jiffies.saturating_add(b.cpu_jiffies);
                    mtd.rx_bytes = mtd.rx_bytes.saturating_add(b.rx_bytes);
                    mtd.tx_bytes = mtd.tx_bytes.saturating_add(b.tx_bytes);
                    mtd.build_seconds = mtd.build_seconds.saturating_add(b.build_seconds);
                    mtd.warm_seconds = mtd.warm_seconds.saturating_add(b.warm_seconds);
                }
                if b.hour_epoch >= newest_hour {
                    newest_hour = b.hour_epoch;
                    mtd.storage_bytes = b.storage_bytes_last;
                }
            }
        }
        Ok(mtd)
    }

    /// Remove buckets whose `hour_epoch` is strictly older than `cutoff_hour`.
    pub fn prune_usage(&self, cutoff_hour: u64) -> Result<usize> {
        let stale: Vec<String> = {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(USAGE)?;
            let mut keys = Vec::new();
            for entry in table.iter()? {
                let (k, v) = entry?;
                let b: UsageBucket = serde_json::from_slice(v.value())?;
                if b.hour_epoch < cutoff_hour {
                    keys.push(k.value().to_string());
                }
            }
            keys
        };
        if stale.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(USAGE)?;
            for k in &stale {
                table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        Ok(stale.len())
    }

    /// Drop all usage buckets for a project (called on project delete).
    pub fn purge_usage(&self, project_id: &str) -> Result<usize> {
        let prefix = format!("{project_id}:");
        let keys: Vec<String> = {
            let txn = self.db.begin_read()?;
            let table = txn.open_table(USAGE)?;
            let mut keys = Vec::new();
            for entry in table.iter()? {
                let (k, _) = entry?;
                if k.value().starts_with(&prefix) {
                    keys.push(k.value().to_string());
                }
            }
            keys
        };
        if keys.is_empty() {
            return Ok(0);
        }
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(USAGE)?;
            for k in &keys {
                table.remove(k.as_str())?;
            }
        }
        txn.commit()?;
        Ok(keys.len())
    }

    // -- Quotas --

    pub fn set_quota(&self, project_id: &str, limits: &QuotaLimits) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(QUOTAS)?;
            let data = serde_json::to_vec(limits)?;
            table.insert(project_id, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_quota_override(&self, project_id: &str) -> Result<Option<QuotaLimits>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(QUOTAS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// The project's effective limits: its override, else [`DEFAULT_QUOTA`].
    pub fn get_quota(&self, project_id: &str) -> Result<QuotaLimits> {
        Ok(self
            .get_quota_override(project_id)?
            .unwrap_or(DEFAULT_QUOTA))
    }

    pub fn remove_quota(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(QUOTAS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Per-project L4 egress limits --

    pub fn set_l4_egress_limits(&self, project_id: &str, limits: &L4EgressLimits) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(L4_EGRESS_LIMITS)?;
            let bytes = serde_json::to_vec(limits)?;
            table.insert(project_id, bytes.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The project's override, or `None` when it has never been given one. Callers layer this over
    /// the platform defaults field-by-field rather than substituting wholesale — see
    /// [`L4EgressLimits`].
    pub fn get_l4_egress_limits(&self, project_id: &str) -> Result<Option<L4EgressLimits>> {
        let txn = self.db.begin_read()?;
        let table = match txn.open_table(L4_EGRESS_LIMITS) {
            Ok(t) => t,
            Err(_) => return Ok(None),
        };
        match table.get(project_id)? {
            Some(v) => Ok(serde_json::from_slice(v.value()).ok()),
            None => Ok(None),
        }
    }

    pub fn remove_l4_egress_limits(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(L4_EGRESS_LIMITS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Per-tenant quotas (warm-VM cap) --

    pub fn set_tenant_quota(&self, tenant_id: &str, limits: &TenantQuotaLimits) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(TENANT_QUOTAS)?;
            let data = serde_json::to_vec(limits)?;
            table.insert(tenant_id, data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_tenant_quota_override(&self, tenant_id: &str) -> Result<Option<TenantQuotaLimits>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANT_QUOTAS)?;
        match table.get(tenant_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// The tenant's effective limits: its override, else [`DEFAULT_TENANT_QUOTA`].
    pub fn get_tenant_quota(&self, tenant_id: &str) -> Result<TenantQuotaLimits> {
        Ok(self
            .get_tenant_quota_override(tenant_id)?
            .unwrap_or(DEFAULT_TENANT_QUOTA))
    }

    pub fn remove_tenant_quota(&self, tenant_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(TENANT_QUOTAS)?;
            table.remove(tenant_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Quota status (enforcement state) --

    pub fn save_quota_status(&self, status: &QuotaStatus) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(QUOTA_STATUS)?;
            let data = serde_json::to_vec(status)?;
            table.insert(status.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_quota_status(&self, project_id: &str) -> Result<Option<QuotaStatus>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(QUOTA_STATUS)?;
        match table.get(project_id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn remove_quota_status(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(QUOTA_STATUS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    // -- Domains --

    pub fn get_domain(&self, host: &str) -> Result<Option<DomainRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DOMAINS)?;
        match table.get(host)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    /// Atomically claim a host: fails if it's already taken. The availability
    /// check and the insert happen in one write txn to avoid a TOCTOU race
    /// between two tenants claiming the same host.
    pub fn claim_domain(&self, record: &DomainRecord) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let claimed = {
            let mut table = txn.open_table(DOMAINS)?;
            if table.get(record.host.as_str())?.is_some() {
                false
            } else {
                let data = serde_json::to_vec(record)?;
                table.insert(record.host.as_str(), data.as_slice())?;
                true
            }
        };
        txn.commit()?;
        Ok(claimed)
    }

    /// Overwrite an existing record (e.g. flipping Pending → Active on verify).
    pub fn save_domain(&self, record: &DomainRecord) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DOMAINS)?;
            let data = serde_json::to_vec(record)?;
            table.insert(record.host.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn remove_domain(&self, host: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(DOMAINS)?;
            table.remove(host)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn list_all_domains(&self) -> Result<Vec<DomainRecord>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DOMAINS)?;
        let mut out = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            out.push(serde_json::from_slice::<DomainRecord>(value.value())?);
        }
        Ok(out)
    }

    pub fn list_domains_for_project(&self, project_id: &str) -> Result<Vec<DomainRecord>> {
        Ok(self
            .list_all_domains()?
            .into_iter()
            .filter(|d| d.project_id == project_id)
            .collect())
    }

    pub fn list_active_domains_for_project(&self, project_id: &str) -> Result<Vec<DomainRecord>> {
        Ok(self
            .list_domains_for_project(project_id)?
            .into_iter()
            .filter(|d| d.status == DomainStatus::Active)
            .collect())
    }

    /// True if `host` can be claimed: not reserved and not already registered.
    pub fn host_key_available(&self, host: &str) -> Result<bool> {
        if host_is_reserved(host) {
            return Ok(false);
        }
        Ok(self.get_domain(host)?.is_none())
    }

    pub fn create_tenant(&self, tenant: &Tenant) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(TENANTS)?;
            let data = serde_json::to_vec(tenant)?;
            table.insert(tenant.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn get_tenant(&self, id: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        match table.get(id)? {
            Some(data) => Ok(Some(serde_json::from_slice(data.value())?)),
            None => Ok(None),
        }
    }

    pub fn list_tenants(&self) -> Result<Vec<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        let mut tenants = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let tenant: Tenant = serde_json::from_slice(value.value())?;
            tenants.push(tenant);
        }
        Ok(tenants)
    }

    pub fn save_api_token(&self, token: &ApiToken) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(API_TOKENS)?;
            let data = serde_json::to_vec(token)?;
            table.insert(token.id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn find_tenant_by_email(&self, email: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(TENANTS)?;
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let tenant: Tenant = serde_json::from_slice(value.value())?;
            if tenant.email == email {
                return Ok(Some(tenant));
            }
        }
        Ok(None)
    }

    pub fn list_projects_for_tenant(&self, tenant_id: &str) -> Result<Vec<Project>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(PROJECTS)?;
        let mut projects = Vec::new();
        for entry in table.iter()? {
            let (_key, value) = entry?;
            let project: Project = serde_json::from_slice(value.value())?;
            if project.tenant_id.as_deref() == Some(tenant_id) {
                projects.push(project);
            }
        }
        Ok(projects)
    }

    // -- Secrets --

    pub fn set_secret(&self, project_id: &str, key: &str, value: &str) -> Result<()> {
        let compound_key = format!("{project_id}:{key}");
        let secret = Secret {
            project_id: project_id.to_string(),
            key: key.to_string(),
            value: value.to_string(),
        };
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(SECRETS)?;
            let data = serde_json::to_vec(&secret)?;
            table.insert(compound_key.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    pub fn list_secrets(&self, project_id: &str) -> Result<Vec<Secret>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(SECRETS)?;
        let prefix = format!("{project_id}:");
        let mut secrets = Vec::new();
        for entry in table.iter()? {
            let (key, value) = entry?;
            if key.value().starts_with(&prefix) {
                let secret: Secret = serde_json::from_slice(value.value())?;
                secrets.push(secret);
            }
        }
        Ok(secrets)
    }

    pub fn delete_secret(&self, project_id: &str, key: &str) -> Result<bool> {
        let compound_key = format!("{project_id}:{key}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(SECRETS)?;
            table.remove(compound_key.as_str())?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Remove ALL of a project's secrets (project teardown). The compound key is
    /// `{project_id}:{key}`, and the `:` separator makes the prefix exact — project
    /// `forumall` never matches `forumall2:*`. Returns the number removed. Without
    /// this, a recreated project of the same slug would inherit a prior tenant's
    /// secrets (which the deploy path injects into the container env).
    pub fn delete_all_secrets(&self, project_id: &str) -> Result<usize> {
        let prefix = format!("{project_id}:");
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut table = txn.open_table(SECRETS)?;
            // Collect first: redb forbids mutating the table while its iterator is live.
            let keys: Vec<String> = table
                .iter()?
                .filter_map(|e| e.ok())
                .map(|(k, _)| k.value().to_string())
                .filter(|k| k.starts_with(&prefix))
                .collect();
            for k in keys {
                if table.remove(k.as_str())?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- Object-store access keys --

    /// Hard cap on the number of S3 access keys a single project may hold. Prevents
    /// unbounded index growth and limits the blast radius of a compromised tenant.
    pub const MAX_ACCESS_KEYS_PER_PROJECT: usize = 25;

    /// Count the access keys that exist for `project_id` using a bounded range scan
    /// over the `ACCESS_KEYS_BY_PROJECT` index.  Index keys are
    /// `"{project_id}:{akid}"`, so the half-open range
    /// `["{project_id}:" .. "{project_id};")`  (';' == ':' + 1) contains exactly
    /// this project's entries and nothing else.
    pub fn count_access_keys(&self, project_id: &str) -> Result<usize> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let count = index.range(lo.as_str()..hi.as_str())?.count();
        Ok(count)
    }

    /// Mint a new access key for `project_id`. Returns the full record INCLUDING the
    /// secret — the only time it's exposed (the caller shows it once). Writes the
    /// primary (`ACCESS_KEYS`) and per-project index (`ACCESS_KEYS_BY_PROJECT`) in a
    /// single txn so they can never diverge.
    ///
    /// Returns an error if the project already holds [`Self::MAX_ACCESS_KEYS_PER_PROJECT`]
    /// keys; the check and insert share a write txn so the count is exact.
    pub fn create_access_key(
        &self,
        project_id: &str,
        tenant_id: &str,
        label: &str,
    ) -> Result<AccessKey> {
        let key = AccessKey {
            access_key_id: auth::generate_access_key_id(),
            project_id: project_id.to_string(),
            tenant_id: tenant_id.to_string(),
            secret_key: auth::generate_secret_access_key(),
            label: label.to_string(),
            created_unix: auth::timestamp(),
        };
        let index_key = format!("{}:{}", project_id, key.access_key_id);
        let txn = self.db.begin_write()?;
        {
            let lo = format!("{project_id}:");
            let hi = format!("{project_id};");
            // Open the index once as mutable; check the cap then insert — same table
            // guard, so redb won't see a double-open.
            let mut index = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
            let current = index.range(lo.as_str()..hi.as_str())?.count();
            if current >= Self::MAX_ACCESS_KEYS_PER_PROJECT {
                return Err(anyhow::anyhow!(
                    "access key limit reached ({} per project)",
                    Self::MAX_ACCESS_KEYS_PER_PROJECT
                ));
            }

            let mut primary = txn.open_table(ACCESS_KEYS)?;
            // Astronomically unlikely, but never silently clobber a live key.
            if primary.get(key.access_key_id.as_str())?.is_some() {
                return Err(anyhow::anyhow!("access key id collision; retry"));
            }
            let data = serde_json::to_vec(&key)?;
            primary.insert(key.access_key_id.as_str(), data.as_slice())?;
            index.insert(index_key.as_str(), key.access_key_id.as_bytes())?;
        }
        txn.commit()?;
        Ok(key)
    }

    /// Stable access-key id for a project's PLATFORM-MANAGED own-bucket binding credential
    /// (the `jkbase:objectstore/store` function binding). Deterministic so each deploy
    /// OVERWRITES the same primary record (rotating the secret) instead of accumulating keys.
    pub fn binding_access_key_id(project_id: &str) -> String {
        format!("JKBND-{project_id}")
    }

    /// Mint (or rotate) the project's own-bucket binding credential. Unlike a user access
    /// key this is stored ONLY in the primary `ACCESS_KEYS` table, NOT the per-project index
    /// — so it is invisible to [`Self::list_access_keys`], never counts against the per-project
    /// cap, and is purged via the stable id on teardown. It is owner-bound (`tenant_id`) and
    /// re-minted with a fresh secret on every deploy; the SigV4 path resolves it via
    /// [`Self::lookup_access_key`] like any key and the object-store owner re-bind fail-closes
    /// an orphaned one. P0-OBJ-NO-STANDING-KEY (phase-1 form: a platform-managed,
    /// deploy-rotated, not-user-visible credential — never the user's own standing key).
    pub fn mint_binding_key(&self, project_id: &str, tenant_id: &str) -> Result<AccessKey> {
        let key = AccessKey {
            access_key_id: Self::binding_access_key_id(project_id),
            project_id: project_id.to_string(),
            tenant_id: tenant_id.to_string(),
            secret_key: auth::generate_secret_access_key(),
            label: "__binding".to_string(),
            created_unix: auth::timestamp(),
        };
        let txn = self.db.begin_write()?;
        {
            // Overwrite any prior binding key = rotation. Primary only (no index entry).
            let mut primary = txn.open_table(ACCESS_KEYS)?;
            let data = serde_json::to_vec(&key)?;
            primary.insert(key.access_key_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(key)
    }

    /// Resolve an access-key id to its full record (incl. project + secret). The
    /// O(1) lookup the object-store SigV4 path performs on every request. `None` if
    /// the key is unknown or was revoked.
    pub fn lookup_access_key(&self, access_key_id: &str) -> Result<Option<AccessKey>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(ACCESS_KEYS)?;
        match table.get(access_key_id)? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
            None => Ok(None),
        }
    }

    /// List a project's access keys (for the console / CLI). Secrets are included in
    /// the record but the API layer must NOT surface them after creation.
    ///
    /// Uses a bounded range scan over the index — O(keys-for-this-project), not
    /// O(all keys across all tenants).
    pub fn list_access_keys(&self, project_id: &str) -> Result<Vec<AccessKey>> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
        let primary = txn.open_table(ACCESS_KEYS)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let mut out = Vec::new();
        for entry in index.range(lo.as_str()..hi.as_str())? {
            let (_k, v) = entry?;
            let akid = String::from_utf8_lossy(v.value()).into_owned();
            if let Some(rec) = primary.get(akid.as_str())? {
                out.push(serde_json::from_slice::<AccessKey>(rec.value())?);
            }
        }
        out.sort_by_key(|a| a.created_unix);
        Ok(out)
    }

    /// Revoke one access key. Scoped to `project_id` via the index compound key, so a
    /// tenant can't revoke another project's key by guessing its id. Returns whether
    /// it existed for this project.
    pub fn delete_access_key(&self, project_id: &str, access_key_id: &str) -> Result<bool> {
        let index_key = format!("{project_id}:{access_key_id}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut index = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
            // Only touch the primary record if the key really belongs to this project.
            let owned = index.remove(index_key.as_str())?.is_some();
            if owned {
                let mut primary = txn.open_table(ACCESS_KEYS)?;
                primary.remove(access_key_id)?;
            }
            owned
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Revoke ALL of a project's access keys (project teardown). Mirrors
    /// [`Self::delete_all_secrets`]: collect-then-delete (redb forbids mutating a
    /// table mid-iteration). Without this, a recreated project of the same slug could
    /// inherit a prior tenant's keys — a cross-tenant object-store breach.
    ///
    /// Uses a bounded range scan — O(keys-for-this-project), not O(all keys).
    pub fn delete_all_access_keys(&self, project_id: &str) -> Result<usize> {
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut index = txn.open_table(ACCESS_KEYS_BY_PROJECT)?;
            // Collect first: redb forbids mutating a table while its iterator is live.
            let entries: Vec<(String, String)> = index
                .range(lo.as_str()..hi.as_str())?
                .filter_map(|e| e.ok())
                .map(|(k, v)| {
                    (
                        k.value().to_string(),
                        String::from_utf8_lossy(v.value()).into_owned(),
                    )
                })
                .collect();
            let mut primary = txn.open_table(ACCESS_KEYS)?;
            for (index_key, akid) in entries {
                index.remove(index_key.as_str())?;
                if primary.remove(akid.as_str())?.is_some() {
                    removed += 1;
                }
            }
            // The platform-managed binding key lives outside the index — purge it by its
            // stable id so a recreated same-slug project never inherits it (the owner re-bind
            // is the backstop, but don't leave a stale credential behind).
            if primary
                .remove(Self::binding_access_key_id(project_id).as_str())?
                .is_some()
            {
                removed += 1;
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- Managed-DB reach-plane access keys (owner-held; see [`DbAccessKey`]) --

    /// Hard cap on DB access keys per project (mirrors [`Self::MAX_ACCESS_KEYS_PER_PROJECT`]):
    /// bounds index growth and a compromised owner's blast radius.
    pub const MAX_DB_ACCESS_KEYS_PER_PROJECT: usize = 25;

    /// Count a project's DB access keys via a bounded range scan over the index.
    pub fn count_db_access_keys(&self, project_id: &str) -> Result<usize> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let count = index.range(lo.as_str()..hi.as_str())?.count();
        Ok(count)
    }

    /// Mint a DB access key for `project_id`. Returns `(record, secret)` — the 240-bit
    /// plaintext `secret` is exposed ONLY here (the caller shows it once); the record
    /// persists just its sha256 fingerprint ([R4]). Primary + per-project index written in
    /// one txn (cap check shares it, so the count is exact). Errs at the per-project cap or
    /// on the astronomically unlikely id collision.
    pub fn create_db_access_key(
        &self,
        project_id: &str,
        tenant_id: &str,
        label: &str,
    ) -> Result<(DbAccessKey, String)> {
        let secret = auth::generate_db_secret();
        let key = DbAccessKey {
            access_key_id: auth::generate_db_access_key_id(),
            project_id: project_id.to_string(),
            tenant_id: tenant_id.to_string(),
            token_fingerprint: auth::token_fingerprint(&secret),
            label: label.to_string(),
            created_unix: auth::timestamp(),
        };
        let index_key = format!("{}:{}", project_id, key.access_key_id);
        let txn = self.db.begin_write()?;
        {
            let lo = format!("{project_id}:");
            let hi = format!("{project_id};");
            let mut index = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
            let current = index.range(lo.as_str()..hi.as_str())?.count();
            if current >= Self::MAX_DB_ACCESS_KEYS_PER_PROJECT {
                return Err(anyhow::anyhow!(
                    "db access key limit reached ({} per project)",
                    Self::MAX_DB_ACCESS_KEYS_PER_PROJECT
                ));
            }
            let mut primary = txn.open_table(DB_ACCESS_KEYS)?;
            if primary.get(key.access_key_id.as_str())?.is_some() {
                return Err(anyhow::anyhow!("db access key id collision; retry"));
            }
            let data = serde_json::to_vec(&key)?;
            primary.insert(key.access_key_id.as_str(), data.as_slice())?;
            index.insert(index_key.as_str(), key.access_key_id.as_bytes())?;
        }
        txn.commit()?;
        Ok((key, secret))
    }

    /// Resolve a DB access-key id to its record — the O(1) lookup the reach-plane edge
    /// performs per connection. `None` if unknown/revoked. Consults ONLY the DB keyspace,
    /// so an S3 `JKBA…` id will not resolve here ([R2]).
    pub fn lookup_db_access_key(&self, access_key_id: &str) -> Result<Option<DbAccessKey>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DB_ACCESS_KEYS)?;
        match table.get(access_key_id)? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
            None => Ok(None),
        }
    }

    /// List a project's DB access keys (console / CLI). Bounded range scan over the index;
    /// records carry only fingerprints, so there is no secret to leak.
    pub fn list_db_access_keys(&self, project_id: &str) -> Result<Vec<DbAccessKey>> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
        let primary = txn.open_table(DB_ACCESS_KEYS)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let mut out = Vec::new();
        for entry in index.range(lo.as_str()..hi.as_str())? {
            let (_k, v) = entry?;
            let akid = String::from_utf8_lossy(v.value()).into_owned();
            if let Some(rec) = primary.get(akid.as_str())? {
                out.push(serde_json::from_slice::<DbAccessKey>(rec.value())?);
            }
        }
        out.sort_by_key(|a| a.created_unix);
        Ok(out)
    }

    /// Revoke one DB access key, scoped to `project_id` via the index compound key (a
    /// tenant can't revoke another project's key by guessing its id). Returns whether it
    /// existed for this project. NB [R5]: tearing down LIVE relays on revoke is the
    /// reach-plane edge's job; this removes only the credential record.
    pub fn delete_db_access_key(&self, project_id: &str, access_key_id: &str) -> Result<bool> {
        let index_key = format!("{project_id}:{access_key_id}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut index = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
            let owned = index.remove(index_key.as_str())?.is_some();
            if owned {
                let mut primary = txn.open_table(DB_ACCESS_KEYS)?;
                primary.remove(access_key_id)?;
            }
            owned
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Revoke ALL of a project's DB access keys (project teardown). Mirrors
    /// [`Self::delete_all_access_keys`] (collect-then-delete; redb forbids mutating a table
    /// mid-iteration). Without this, a recreated same-slug project could inherit a prior
    /// tenant's DB credential.
    pub fn delete_all_db_access_keys(&self, project_id: &str) -> Result<usize> {
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut index = txn.open_table(DB_ACCESS_KEYS_BY_PROJECT)?;
            let entries: Vec<(String, String)> = index
                .range(lo.as_str()..hi.as_str())?
                .filter_map(|e| e.ok())
                .map(|(k, v)| {
                    (
                        k.value().to_string(),
                        String::from_utf8_lossy(v.value()).into_owned(),
                    )
                })
                .collect();
            let mut primary = txn.open_table(DB_ACCESS_KEYS)?;
            for (index_key, akid) in entries {
                index.remove(index_key.as_str())?;
                if primary.remove(akid.as_str())?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- Managed-DB reach-plane splice secret ([R3]) --

    /// Mint (rotate) a project's splice secret: generate a fresh value, persist it, and
    /// return it so the SAME value can be baked into the per-VM metadata image in the
    /// same deploy. Mirrors [`Self::mint_binding_key`].
    pub fn mint_db_splice_secret(&self, project_id: &str) -> Result<String> {
        let secret = auth::generate_splice_secret();
        self.set_db_splice_secret(project_id, &secret)?;
        Ok(secret)
    }

    /// Set (overwrite) a project's host→agent splice secret. Called at deploy with the
    /// SAME value baked into the per-VM metadata image, so edge and agent agree.
    pub fn set_db_splice_secret(&self, project_id: &str, secret: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_SPLICE)?;
            table.insert(project_id, secret.as_bytes())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The project's current splice secret, or `None` if it has no managed DB / none set.
    /// The edge presents this on the `/_jkbase/db` upgrade; a `None` (or a mismatch with
    /// the agent's baked copy) makes the splice fail closed — never open.
    pub fn get_db_splice_secret(&self, project_id: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DB_SPLICE)?;
        match table.get(project_id)? {
            Some(v) => Ok(Some(String::from_utf8_lossy(v.value()).into_owned())),
            None => Ok(None),
        }
    }

    /// Drop a project's splice secret (teardown), so a recreated same-slug project can't
    /// inherit it.
    pub fn delete_db_splice_secret(&self, project_id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_SPLICE)?;
            table.remove(project_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Record the managed-DB tier (`"colocated"` | `"dedicated"`) a deploy just committed, so the
    /// NEXT deploy can detect an in-place tier flip. See [`DB_DEPLOYED_TIER`].
    pub fn set_deployed_tier(&self, project_id: &str, tier: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_DEPLOYED_TIER)?;
            table.insert(project_id, tier.as_bytes())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// The tier the project's last successful deploy committed, or `None` (first deploy / pre-P2).
    pub fn get_deployed_tier(&self, project_id: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DB_DEPLOYED_TIER)?;
        match table.get(project_id)? {
            Some(v) => Ok(Some(String::from_utf8_lossy(v.value()).into_owned())),
            None => Ok(None),
        }
    }

    /// Drop a project's recorded tier (teardown), so a recreated same-slug project starts fresh.
    pub fn delete_deployed_tier(&self, project_id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_DEPLOYED_TIER)?;
            table.remove(project_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // -- Managed-DB rhypedb admin token ([RB1]) --

    /// Mint (rotate) a project's rhypedb admin token: fresh value, persisted, and returned so
    /// the SAME value can be baked into the per-VM metadata image in the same deploy. Mirrors
    /// [`Self::mint_db_splice_secret`].
    pub fn mint_db_admin_token(&self, project_id: &str) -> Result<String> {
        let token = auth::generate_rhypedb_admin_token();
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_ADMIN_TOKEN)?;
            table.insert(project_id, token.as_bytes())?;
        }
        txn.commit()?;
        Ok(token)
    }

    /// The project's current rhypedb admin token, or `None` if it has no managed DB / none
    /// set. The backup executor presents this as `Authorization: Bearer` when it drives the
    /// agent's backup pull; `None` ⇒ backups fail closed (never a plaintext admin call).
    pub fn get_db_admin_token(&self, project_id: &str) -> Result<Option<String>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(DB_ADMIN_TOKEN)?;
        match table.get(project_id)? {
            Some(v) => Ok(Some(String::from_utf8_lossy(v.value()).into_owned())),
            None => Ok(None),
        }
    }

    /// Drop a project's admin token (teardown), so a recreated same-slug project can't inherit
    /// it (and a leaked token is dead once the project is gone).
    pub fn delete_db_admin_token(&self, project_id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(DB_ADMIN_TOKEN)?;
            table.remove(project_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // -- jkbase-Auth signing keys (P3; see [`SigningKeyState`], P0-AUTH-2/4) --

    /// Rotation overlap window: a rotated-out key's PUBLIC half stays in JWKS this long so no live
    /// token is stranded (P0-AUTH-4). ≥ the max token TTL (24h) + clock skew.
    pub const AUTH_SIGNING_ROTATION_WINDOW_SECS: u64 = 24 * 3600 + 300;

    /// Hard cap on retiring public keys kept in a project's key state — bounds the persisted blob
    /// against a pathological rotate-in-a-loop. In-window keys past this many rotations are dropped
    /// oldest-first (only reachable by >32 rotations inside the 24h window, absurd for a signing key).
    pub const MAX_RETIRING_SIGNING_KEYS: usize = 32;

    /// Hard cap on issuer keys per project (mirrors [`Self::MAX_DB_ACCESS_KEYS_PER_PROJECT`]):
    /// bounds index growth and a compromised owner's blast radius.
    pub const MAX_AUTH_ISSUER_KEYS_PER_PROJECT: usize = 25;

    fn stored_key_from_seed(kid: String, seed: [u8; 32], now: u64) -> StoredSigningKey {
        let public = jose::SigningKeypair::from_seed(kid.clone(), seed).public_bytes();
        StoredSigningKey {
            kid,
            seed_b64: B64URL.encode(seed),
            public_b64: B64URL.encode(public),
            created_unix: now,
        }
    }

    fn keypair_from_stored(sk: &StoredSigningKey) -> Result<jose::SigningKeypair> {
        let raw = B64URL
            .decode(sk.seed_b64.as_bytes())
            .context("corrupt signing-key seed")?;
        let seed: [u8; 32] = raw
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("signing-key seed not 32 bytes"))?;
        Ok(jose::SigningKeypair::from_seed(sk.kid.clone(), seed))
    }

    /// A public JWK straight from stored `public_b64` (which is already the JWK `x` value), so a
    /// retiring key (whose private seed is gone) can still be published.
    fn jwk_from_public(kid: &str, public_b64: &str) -> jose::Jwk {
        jose::Jwk {
            kty: "OKP".into(),
            crv: "Ed25519".into(),
            use_: "sig".into(),
            alg: jose::ALG_EDDSA.into(),
            kid: kid.into(),
            x: public_b64.to_string(),
        }
    }

    /// The project's signing-key state, or `None` if it has never minted a token.
    pub fn get_signing_state(&self, project_id: &str) -> Result<Option<SigningKeyState>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(AUTH_SIGNING_KEYS)?;
        match table.get(project_id)? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
            None => Ok(None),
        }
    }

    /// Load-or-mint the project's CURRENT signing keypair (lazy provision on first token mint). The
    /// private seed never leaves this process (P0-AUTH-2). The redb write txn serializes concurrent
    /// mints, so two callers can't race two serial-0 keys into existence.
    pub fn ensure_signing_key(&self, project_id: &str, now: u64) -> Result<jose::SigningKeypair> {
        // Fast path: after the first mint the key ALWAYS exists, so the steady state is a pure read.
        // Taking the global write lock + a durable commit on every mint would serialize all mints
        // (and every other control-plane write) through redb's single writer — a cross-tenant
        // throughput ceiling on the hot "signing oracle" path. Only the rare first-mint escalates.
        if let Some(state) = self.get_signing_state(project_id)? {
            return Self::keypair_from_stored(&state.current);
        }
        let txn = self.db.begin_write()?;
        let keypair = {
            let mut table = txn.open_table(AUTH_SIGNING_KEYS)?;
            // Re-check under the write lock: a concurrent first-mint may have provisioned the key
            // between our read above and acquiring this txn. redb serializes writers, so the loser
            // reads the winner's key instead of clobbering it (closes the TOCTOU).
            let existing: Option<SigningKeyState> = match table.get(project_id)? {
                Some(v) => Some(serde_json::from_slice(v.value())?),
                None => None,
            };
            match existing {
                Some(state) => Self::keypair_from_stored(&state.current)?,
                None => {
                    let kid = format!("{project_id}.0");
                    let seed = auth::generate_signing_seed();
                    let stored = Self::stored_key_from_seed(kid.clone(), seed, now);
                    let state = SigningKeyState {
                        current: stored,
                        retiring: Vec::new(),
                        next_serial: 1,
                    };
                    table.insert(project_id, serde_json::to_vec(&state)?.as_slice())?;
                    jose::SigningKeypair::from_seed(kid, seed)
                }
            }
        };
        txn.commit()?;
        Ok(keypair)
    }

    /// Build the project's public JWKS (current + previous-if-still-in-window). Empty `{keys:[]}` if
    /// the project has never minted — fail-closed (verifies nothing). Callers 404 a NONEXISTENT
    /// project before calling; an existing-but-unprovisioned project legitimately has an empty set.
    pub fn get_jwks(&self, project_id: &str, now: u64) -> Result<jose::Jwks> {
        let state = match self.get_signing_state(project_id)? {
            Some(s) => s,
            None => return Ok(jose::Jwks::default()),
        };
        let mut keys = vec![Self::jwk_from_public(
            &state.current.kid,
            &state.current.public_b64,
        )];
        for r in &state.retiring {
            if now < r.retire_at {
                keys.push(Self::jwk_from_public(&r.kid, &r.public_b64));
            }
        }
        Ok(jose::Jwks::new(keys))
    }

    /// Rotate the project's signing key (P0-AUTH-4). Mints a fresh CURRENT keypair under the next
    /// kid serial; the outgoing key's PUBLIC half becomes PREVIOUS with a retirement window (so live
    /// tokens keep verifying) UNLESS `hard` (compromise) — then it's dropped immediately (hard
    /// revoke). Provisions serial 0 if the project had no key yet. Returns the new keypair.
    pub fn rotate_signing_key(
        &self,
        project_id: &str,
        now: u64,
        hard: bool,
    ) -> Result<jose::SigningKeypair> {
        let txn = self.db.begin_write()?;
        let keypair = {
            let mut table = txn.open_table(AUTH_SIGNING_KEYS)?;
            let existing: Option<SigningKeyState> = match table.get(project_id)? {
                Some(v) => Some(serde_json::from_slice(v.value())?),
                None => None,
            };
            let (serial, retiring) = match existing {
                Some(state) => {
                    let retiring = if hard {
                        // Compromise: drop EVERY rotated-out key from JWKS immediately (hard revoke).
                        Vec::new()
                    } else {
                        // Carry forward the still-in-window retiring keys (so a prior soft rotation's
                        // cohort isn't stranded — P0-AUTH-4), prune expired ones, and add the
                        // outgoing current. Bound the set oldest-first against rotate-in-a-loop.
                        let mut r: Vec<RetiringKey> = state
                            .retiring
                            .into_iter()
                            .filter(|k| now < k.retire_at)
                            .collect();
                        r.push(RetiringKey {
                            kid: state.current.kid.clone(),
                            public_b64: state.current.public_b64.clone(),
                            retire_at: now + Self::AUTH_SIGNING_ROTATION_WINDOW_SECS,
                        });
                        if r.len() > Self::MAX_RETIRING_SIGNING_KEYS {
                            let overflow = r.len() - Self::MAX_RETIRING_SIGNING_KEYS;
                            r.drain(0..overflow);
                        }
                        r
                    };
                    (state.next_serial, retiring)
                }
                None => (0, Vec::new()),
            };
            let kid = format!("{project_id}.{serial}");
            let seed = auth::generate_signing_seed();
            let stored = Self::stored_key_from_seed(kid.clone(), seed, now);
            let state = SigningKeyState {
                current: stored,
                retiring,
                next_serial: serial + 1,
            };
            table.insert(project_id, serde_json::to_vec(&state)?.as_slice())?;
            jose::SigningKeypair::from_seed(kid, seed)
        };
        txn.commit()?;
        Ok(keypair)
    }

    /// Drop the project's signing key entirely (teardown), so a recreated same-slug project starts
    /// with a fresh keypair and any token still bearing an old kid fails closed (unknown kid).
    pub fn delete_signing_key(&self, project_id: &str) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(AUTH_SIGNING_KEYS)?;
            table.remove(project_id)?;
        }
        txn.commit()?;
        Ok(())
    }

    // -- jkbase-Auth issuer keys (P3; see [`IssuerKey`], P0-AUTH-3) --

    /// Count a project's issuer keys via a bounded range scan over the index.
    pub fn count_issuer_keys(&self, project_id: &str) -> Result<usize> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        Ok(index.range(lo.as_str()..hi.as_str())?.count())
    }

    /// Mint an issuer key for `project_id`. Returns `(record, secret)` — the 256-bit `jkbk_`
    /// plaintext is exposed ONLY here (shown once); the record persists just its sha256 fingerprint
    /// ([R4]). Primary (keyed by fingerprint for an O(1) auth lookup) + per-project index written in
    /// one txn. Errs at the per-project cap.
    pub fn create_issuer_key(
        &self,
        project_id: &str,
        tenant_id: &str,
        label: &str,
    ) -> Result<(IssuerKey, String)> {
        let secret = auth::generate_issuer_key();
        let key = IssuerKey {
            key_id: auth::generate_issuer_key_id(),
            project_id: project_id.to_string(),
            tenant_id: tenant_id.to_string(),
            token_fingerprint: auth::token_fingerprint(&secret),
            label: label.to_string(),
            created_unix: auth::timestamp(),
        };
        let index_key = format!("{}:{}", project_id, key.key_id);
        let txn = self.db.begin_write()?;
        {
            let lo = format!("{project_id}:");
            let hi = format!("{project_id};");
            let mut index = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
            let current = index.range(lo.as_str()..hi.as_str())?.count();
            if current >= Self::MAX_AUTH_ISSUER_KEYS_PER_PROJECT {
                return Err(anyhow::anyhow!(
                    "issuer key limit reached ({} per project)",
                    Self::MAX_AUTH_ISSUER_KEYS_PER_PROJECT
                ));
            }
            let mut primary = txn.open_table(AUTH_ISSUER_KEYS)?;
            if primary.get(key.token_fingerprint.as_str())?.is_some() {
                return Err(anyhow::anyhow!("issuer key collision; retry"));
            }
            let data = serde_json::to_vec(&key)?;
            primary.insert(key.token_fingerprint.as_str(), data.as_slice())?;
            index.insert(index_key.as_str(), key.token_fingerprint.as_bytes())?;
        }
        txn.commit()?;
        Ok((key, secret))
    }

    /// Resolve a presented `jkbk_` secret to its issuer-key record — the O(1) lookup the mint path
    /// performs (the primary is keyed by the secret's fingerprint, so the get IS the credential
    /// check). `None` if unknown/revoked. The caller then re-binds to the project's current owner
    /// (P0-AUTH-3) and cross-checks the path project id.
    pub fn lookup_issuer_key_by_secret(&self, secret: &str) -> Result<Option<IssuerKey>> {
        let fp = auth::token_fingerprint(secret);
        let txn = self.db.begin_read()?;
        let table = txn.open_table(AUTH_ISSUER_KEYS)?;
        match table.get(fp.as_str())? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
            None => Ok(None),
        }
    }

    /// List a project's issuer keys (console/CLI). Records carry only fingerprints — no secret to
    /// leak. Bounded range scan over the index.
    pub fn list_issuer_keys(&self, project_id: &str) -> Result<Vec<IssuerKey>> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
        let primary = txn.open_table(AUTH_ISSUER_KEYS)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let mut out = Vec::new();
        for entry in index.range(lo.as_str()..hi.as_str())? {
            let (_k, v) = entry?;
            let fp = String::from_utf8_lossy(v.value()).into_owned();
            if let Some(rec) = primary.get(fp.as_str())? {
                out.push(serde_json::from_slice::<IssuerKey>(rec.value())?);
            }
        }
        out.sort_by_key(|k| k.created_unix);
        Ok(out)
    }

    /// Revoke one issuer key, scoped to `project_id` via the index compound key (a tenant can't
    /// revoke another project's key by guessing its id). Returns whether it existed for this project.
    pub fn delete_issuer_key(&self, project_id: &str, key_id: &str) -> Result<bool> {
        let index_key = format!("{project_id}:{key_id}");
        let txn = self.db.begin_write()?;
        let existed = {
            let mut index = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
            match index.remove(index_key.as_str())? {
                Some(guard) => {
                    let fp = String::from_utf8_lossy(guard.value()).into_owned();
                    let mut primary = txn.open_table(AUTH_ISSUER_KEYS)?;
                    primary.remove(fp.as_str())?;
                    true
                }
                None => false,
            }
        };
        txn.commit()?;
        Ok(existed)
    }

    /// Revoke ALL of a project's issuer keys (teardown). Collect-then-delete (redb forbids mutating
    /// a table mid-iteration). Without this, a recreated same-slug project could inherit a prior
    /// tenant's issuer credential.
    pub fn delete_all_issuer_keys(&self, project_id: &str) -> Result<usize> {
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let txn = self.db.begin_write()?;
        let mut removed = 0usize;
        {
            let mut index = txn.open_table(AUTH_ISSUER_KEYS_BY_PROJECT)?;
            let entries: Vec<(String, String)> = index
                .range(lo.as_str()..hi.as_str())?
                .filter_map(|e| e.ok())
                .map(|(k, v)| {
                    (
                        k.value().to_string(),
                        String::from_utf8_lossy(v.value()).into_owned(),
                    )
                })
                .collect();
            let mut primary = txn.open_table(AUTH_ISSUER_KEYS)?;
            for (index_key, fp) in entries {
                index.remove(index_key.as_str())?;
                if primary.remove(fp.as_str())?.is_some() {
                    removed += 1;
                }
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- Managed-DB backup catalog ([RB6]/[RB8]) --

    /// Hard cap on retained backups per project (retention bound). The nightly loop prunes to
    /// this; on-demand backups past it are refused (mirrors [`Self::MAX_DB_ACCESS_KEYS_PER_PROJECT`]).
    pub const MAX_DB_BACKUPS_PER_PROJECT: usize = 30;

    /// Record a new `Pending` backup row (primary + per-project index in one txn). The caller
    /// (backup executor) then streams the tar and flips status via [`Self::set_db_backup_status`].
    /// Errs at the per-project cap or on an id collision.
    pub fn create_db_backup(
        &self,
        project_id: &str,
        tenant_id: &str,
        backup_id: &str,
        object_key: &str,
    ) -> Result<DbBackup> {
        let rec = DbBackup {
            backup_id: backup_id.to_string(),
            project_id: project_id.to_string(),
            tenant_id: tenant_id.to_string(),
            created_at_ms: auth::timestamp_ms(),
            size_bytes: 0,
            object_key: object_key.to_string(),
            manifest_summary: String::new(),
            status: BackupStatus::Pending,
        };
        let index_key = format!("{project_id}:{backup_id}");
        let txn = self.db.begin_write()?;
        {
            let lo = format!("{project_id}:");
            let hi = format!("{project_id};");
            let mut index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
            if index.range(lo.as_str()..hi.as_str())?.count() >= Self::MAX_DB_BACKUPS_PER_PROJECT {
                return Err(anyhow::anyhow!(
                    "backup limit reached ({} per project); prune older backups first",
                    Self::MAX_DB_BACKUPS_PER_PROJECT
                ));
            }
            let mut primary = txn.open_table(DB_BACKUPS)?;
            if primary.get(backup_id)?.is_some() {
                return Err(anyhow::anyhow!("backup id collision; retry"));
            }
            let data = serde_json::to_vec(&rec)?;
            primary.insert(backup_id, data.as_slice())?;
            index.insert(index_key.as_str(), backup_id.as_bytes())?;
        }
        txn.commit()?;
        Ok(rec)
    }

    /// A backup is considered "in progress" while a `Pending` row younger than this exists —
    /// used for single-flight (one backup per project at a time). A `Pending` row older than
    /// this is treated as stale (the server crashed mid-backup) and no longer blocks a new one.
    pub const BACKUP_STALE_MS: u64 = 30 * 60 * 1000;

    /// True if the project has a non-stale `Pending` backup (single-flight guard). Prevents a
    /// tenant from accumulating 30 concurrent Pending rows and a project from re-firing a backup
    /// while one is running.
    pub fn has_active_backup(&self, project_id: &str) -> Result<bool> {
        let now = auth::timestamp_ms();
        Ok(self.list_db_backups(project_id)?.iter().any(|b| {
            b.status == BackupStatus::Pending
                && now.saturating_sub(b.created_at_ms) < Self::BACKUP_STALE_MS
        }))
    }

    /// Create a `Pending` backup row with a server-authored id + object key ([RB6]). The single
    /// place both the on-demand endpoint and the nightly loop mint a backup, so the object key
    /// is never caller-influenced.
    pub fn create_db_backup_auto(&self, project_id: &str, tenant_id: &str) -> Result<DbBackup> {
        let backup_id = auth::generate_backup_id();
        let object_key = format!("{project_id}/{backup_id}.tar");
        self.create_db_backup(project_id, tenant_id, &backup_id, &object_key)
    }

    /// Resolve a backup by (`project_id`, `backup_id`) via the per-project index key, so a
    /// tenant can't resolve another project's backup by guessing the id ([RB6]). `None` if
    /// unknown for this project.
    pub fn get_db_backup(&self, project_id: &str, backup_id: &str) -> Result<Option<DbBackup>> {
        let index_key = format!("{project_id}:{backup_id}");
        let txn = self.db.begin_read()?;
        let index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
        if index.get(index_key.as_str())?.is_none() {
            return Ok(None);
        }
        let primary = txn.open_table(DB_BACKUPS)?;
        match primary.get(backup_id)? {
            Some(v) => Ok(Some(serde_json::from_slice(v.value())?)),
            None => Ok(None),
        }
    }

    /// List a project's backups (newest first). Bounded range scan over the index.
    pub fn list_db_backups(&self, project_id: &str) -> Result<Vec<DbBackup>> {
        let txn = self.db.begin_read()?;
        let index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
        let primary = txn.open_table(DB_BACKUPS)?;
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let mut out = Vec::new();
        for entry in index.range(lo.as_str()..hi.as_str())? {
            let (_k, v) = entry?;
            let id = String::from_utf8_lossy(v.value()).into_owned();
            if let Some(rec) = primary.get(id.as_str())? {
                out.push(serde_json::from_slice::<DbBackup>(rec.value())?);
            }
        }
        out.sort_by_key(|b| std::cmp::Reverse(b.created_at_ms));
        Ok(out)
    }

    /// Update a backup's status (+ size/summary on completion). Scoped to `project_id` via the
    /// index so a stray call can't mutate another project's row. No-op if the row is gone.
    pub fn set_db_backup_status(
        &self,
        project_id: &str,
        backup_id: &str,
        status: BackupStatus,
        size_bytes: u64,
        manifest_summary: &str,
    ) -> Result<()> {
        let index_key = format!("{project_id}:{backup_id}");
        let txn = self.db.begin_write()?;
        {
            let owned = {
                let index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
                index.get(index_key.as_str())?.is_some()
            };
            if owned {
                let mut primary = txn.open_table(DB_BACKUPS)?;
                let existing = primary
                    .get(backup_id)?
                    .map(|v| serde_json::from_slice::<DbBackup>(v.value()))
                    .transpose()?;
                if let Some(mut rec) = existing {
                    rec.status = status;
                    if size_bytes > 0 {
                        rec.size_bytes = size_bytes;
                    }
                    if !manifest_summary.is_empty() {
                        rec.manifest_summary = manifest_summary.to_string();
                    }
                    let data = serde_json::to_vec(&rec)?;
                    primary.insert(backup_id, data.as_slice())?;
                }
            }
        }
        txn.commit()?;
        Ok(())
    }

    /// Delete one backup row (both tables), scoped to `project_id`. Returns the deleted row so
    /// the caller can GC the blob. NB: the blob deletion is the caller's job ([RB11]).
    pub fn delete_db_backup(&self, project_id: &str, backup_id: &str) -> Result<Option<DbBackup>> {
        let index_key = format!("{project_id}:{backup_id}");
        let txn = self.db.begin_write()?;
        let removed = {
            let mut index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
            if index.remove(index_key.as_str())?.is_none() {
                None
            } else {
                let mut primary = txn.open_table(DB_BACKUPS)?;
                let rec = primary
                    .get(backup_id)?
                    .map(|v| serde_json::from_slice::<DbBackup>(v.value()))
                    .transpose()?;
                primary.remove(backup_id)?;
                rec
            }
        };
        txn.commit()?;
        Ok(removed)
    }

    /// Delete ALL of a project's backup rows (teardown), returning them so the caller GCs the
    /// blobs. Collect-then-delete (redb forbids mutating a table mid-iteration).
    pub fn delete_all_db_backups(&self, project_id: &str) -> Result<Vec<DbBackup>> {
        let lo = format!("{project_id}:");
        let hi = format!("{project_id};");
        let txn = self.db.begin_write()?;
        let mut removed = Vec::new();
        {
            let mut index = txn.open_table(DB_BACKUPS_BY_PROJECT)?;
            let entries: Vec<(String, String)> = index
                .range(lo.as_str()..hi.as_str())?
                .filter_map(|e| e.ok())
                .map(|(k, v)| {
                    (
                        k.value().to_string(),
                        String::from_utf8_lossy(v.value()).into_owned(),
                    )
                })
                .collect();
            let mut primary = txn.open_table(DB_BACKUPS)?;
            for (index_key, id) in entries {
                index.remove(index_key.as_str())?;
                if let Some(v) = primary.get(id.as_str())?
                    && let Ok(rec) = serde_json::from_slice::<DbBackup>(v.value())
                {
                    removed.push(rec);
                }
                primary.remove(id.as_str())?;
            }
        }
        txn.commit()?;
        Ok(removed)
    }

    // -- Connected-repo build triggers (build · D) --

    /// Load a project's repo-trigger credentials, or `None` if it has none yet.
    pub fn get_repo_trigger(&self, project_id: &str) -> Result<Option<RepoTriggerConfig>> {
        let txn = self.db.begin_read()?;
        let table = txn.open_table(REPO_TRIGGERS)?;
        match table.get(project_id)? {
            Some(value) => Ok(Some(serde_json::from_slice(value.value())?)),
            None => Ok(None),
        }
    }

    pub fn save_repo_trigger(&self, cfg: &RepoTriggerConfig) -> Result<()> {
        let txn = self.db.begin_write()?;
        {
            let mut table = txn.open_table(REPO_TRIGGERS)?;
            let data = serde_json::to_vec(cfg)?;
            table.insert(cfg.project_id.as_str(), data.as_slice())?;
        }
        txn.commit()?;
        Ok(())
    }

    /// Remove a project's repo-trigger credentials (project teardown). Returns
    /// whether a record existed.
    pub fn delete_repo_trigger(&self, project_id: &str) -> Result<bool> {
        let txn = self.db.begin_write()?;
        let existed = {
            let mut table = txn.open_table(REPO_TRIGGERS)?;
            table.remove(project_id)?.is_some()
        };
        txn.commit()?;
        Ok(existed)
    }

    pub fn authenticate(&self, raw_token: &str) -> Result<Option<Tenant>> {
        let txn = self.db.begin_read()?;
        let tokens_table = txn.open_table(API_TOKENS)?;
        let tenants_table = txn.open_table(TENANTS)?;

        for entry in tokens_table.iter()? {
            let (_key, value) = entry?;
            let api_token: ApiToken = serde_json::from_slice(value.value())?;
            if auth::verify_token(raw_token, &api_token.token_hash)
                && let Some(tenant_data) = tenants_table.get(api_token.tenant_id.as_str())?
            {
                let tenant: Tenant = serde_json::from_slice(tenant_data.value())?;
                return Ok(Some(tenant));
            }
        }

        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::jose::{self, Claims, VerifyOptions};

    fn tmp_db() -> (Store, std::path::PathBuf) {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::env::temp_dir().join(format!("jkbase-store-test-{nanos}.redb"));
        (Store::open(&path).unwrap(), path)
    }

    fn meta(project: &str, version: u64) -> DeploymentMeta {
        DeploymentMeta {
            project_id: project.to_string(),
            version,
            created_at: version, // arbitrary but ordered
            layer_digests: Vec::new(),
        }
    }

    fn auth_claims(project: &str, now: u64) -> Claims {
        Claims {
            iss: format!("https://auth.jkbase.app/v1/projects/{project}"),
            sub: "end-user-1".into(),
            aud: project.into(),
            iat: now,
            exp: now + 3600,
            jti: "jti".into(),
            claims: None,
        }
    }

    #[test]
    fn l4_port_allocations_crud_sticky_and_quarantine() {
        let (store, _p) = tmp_db();

        let a = |name: &str, ext: u16, pinned: bool| PortAllocation {
            project_id: "proj".into(),
            name: name.into(),
            proto: "udp".into(),
            external_port: ext,
            guest_port: 9987,
            agent_udp_port: 40000 + ext,
            pinned,
            host_id: String::new(),
            placement_epoch: 0,
        };

        // Upsert + get by composite key; host-asserted sticky fields round-trip.
        store.save_port_allocation(&a("voice", 20001, true)).unwrap();
        store.save_port_allocation(&a("alt", 20002, false)).unwrap();
        let got = store.get_port_allocation("proj", "voice").unwrap().unwrap();
        assert_eq!(got.external_port, 20001);
        assert_eq!(got.agent_udp_port, 60001);
        assert!(got.pinned);

        // A same-prefix sibling project must NOT bleed into the per-project range scan.
        store
            .save_port_allocation(&PortAllocation {
                project_id: "proj2".into(),
                name: "voice".into(),
                proto: "udp".into(),
                external_port: 20003,
                guest_port: 9987,
                agent_udp_port: 60003,
                pinned: false,
                host_id: String::new(),
                placement_epoch: 0,
            })
            .unwrap();
        let mine = store.list_port_allocations_for_project("proj").unwrap();
        assert_eq!(mine.len(), 2);
        assert!(mine.iter().all(|p| p.project_id == "proj"));
        assert_eq!(store.list_port_allocations().unwrap().len(), 3);

        // Remove-one then remove-all clears only this project; the sibling survives.
        assert!(store.remove_port_allocation("proj", "alt").unwrap());
        assert_eq!(store.remove_all_port_allocations("proj").unwrap(), 1);
        assert!(store.get_port_allocation("proj", "voice").unwrap().is_none());
        assert_eq!(
            store
                .list_port_allocations_for_project("proj2")
                .unwrap()
                .len(),
            1
        );

        // Reuse quarantine: record → read → prune.
        assert!(store.get_port_quarantine(20001).unwrap().is_none());
        store.quarantine_port(20001, 1_000_000).unwrap();
        assert_eq!(store.get_port_quarantine(20001).unwrap(), Some(1_000_000));
        assert_eq!(
            store.list_port_quarantine().unwrap(),
            vec![(20001, 1_000_000)]
        );
        assert!(store.unquarantine_port(20001).unwrap());
        assert!(store.get_port_quarantine(20001).unwrap().is_none());
    }

    #[test]
    fn signing_key_lazy_provision_sign_and_verify() {
        let (store, _p) = tmp_db();
        let now = 1_000_000;
        assert!(store.get_signing_state("proj").unwrap().is_none());
        // First call provisions serial 0 and returns a usable signer.
        let kp = store.ensure_signing_key("proj", now).unwrap();
        assert_eq!(kp.kid(), "proj.0");
        // Idempotent: a second call returns the SAME key (no rotation, byte-stable).
        let kp2 = store.ensure_signing_key("proj", now + 5).unwrap();
        assert_eq!(kp2.kid(), "proj.0");
        assert_eq!(kp2.public_bytes(), kp.public_bytes());
        // A token it signs verifies against the published JWKS.
        let tok = kp.sign(&auth_claims("proj", now)).unwrap();
        let jwks = store.get_jwks("proj", now).unwrap();
        assert_eq!(jwks.keys.len(), 1);
        let v = jose::verify(&tok, &jwks, &VerifyOptions::at(now + 10)).unwrap();
        assert_eq!(v.kid, "proj.0");
        assert_eq!(v.claims.sub, "end-user-1");
        // An unprovisioned project has an empty JWKS (fail-closed, verifies nothing).
        assert!(store.get_jwks("other", now).unwrap().keys.is_empty());
    }

    #[test]
    fn signing_key_rotation_window() {
        let (store, _p) = tmp_db();
        let now = 1_000_000;
        let old = store.ensure_signing_key("proj", now).unwrap(); // proj.0
        let tok_old = old.sign(&auth_claims("proj", now)).unwrap();

        let new = store.rotate_signing_key("proj", now, false).unwrap(); // proj.1, soft
        assert_eq!(new.kid(), "proj.1");
        assert_ne!(new.public_bytes(), old.public_bytes());

        // In-window JWKS carries BOTH kids → the pre-rotation token still verifies (P0-AUTH-4).
        let jwks_in = store.get_jwks("proj", now).unwrap();
        assert_eq!(jwks_in.keys.len(), 2);
        assert!(jose::verify(&tok_old, &jwks_in, &VerifyOptions::at(now)).is_ok());

        // After the window closes the old kid is gone → the same token fails closed.
        let after = now + Store::AUTH_SIGNING_ROTATION_WINDOW_SECS + 10;
        let jwks_after = store.get_jwks("proj", after).unwrap();
        assert_eq!(jwks_after.keys.len(), 1);
        assert_eq!(jwks_after.keys[0].kid, "proj.1");
        assert_eq!(
            jose::verify(&tok_old, &jwks_after, &VerifyOptions::at(now)).unwrap_err(),
            jose::VerifyError::UnknownKid
        );

        // A HARD rotation (compromise) drops the outgoing key from JWKS immediately.
        let hard = store.rotate_signing_key("proj", now, true).unwrap(); // proj.2
        assert_eq!(hard.kid(), "proj.2");
        let jwks_hard = store.get_jwks("proj", now).unwrap();
        assert_eq!(jwks_hard.keys.len(), 1);
        assert_eq!(jwks_hard.keys[0].kid, "proj.2");
    }

    #[test]
    fn signing_key_double_rotation_keeps_all_in_window_cohorts() {
        // Two soft rotations inside the window must NOT strand the oldest cohort (P0-AUTH-4).
        let (store, _p) = tmp_db();
        let now = 1_000_000;
        let k0 = store.ensure_signing_key("proj", now).unwrap(); // proj.0
        let tok0 = k0.sign(&auth_claims("proj", now)).unwrap();
        let k1 = store.rotate_signing_key("proj", now, false).unwrap(); // proj.1
        let tok1 = k1.sign(&auth_claims("proj", now)).unwrap();
        store.rotate_signing_key("proj", now, false).unwrap(); // proj.2

        // All three kids are published in-window → neither pre-rotation token is stranded.
        let jwks = store.get_jwks("proj", now).unwrap();
        assert_eq!(jwks.keys.len(), 3);
        assert!(jose::verify(&tok0, &jwks, &VerifyOptions::at(now)).is_ok());
        assert!(jose::verify(&tok1, &jwks, &VerifyOptions::at(now)).is_ok());

        // A HARD rotation clears the whole retiring set → both old tokens fail closed at once.
        store.rotate_signing_key("proj", now, true).unwrap(); // proj.3
        let jwks_hard = store.get_jwks("proj", now).unwrap();
        assert_eq!(jwks_hard.keys.len(), 1);
        assert_eq!(
            jose::verify(&tok0, &jwks_hard, &VerifyOptions::at(now)).unwrap_err(),
            jose::VerifyError::UnknownKid
        );
    }

    #[test]
    fn issuer_key_create_lookup_and_owner_binding() {
        let (store, _p) = tmp_db();
        let (rec, secret) = store.create_issuer_key("proj", "tenantA", "web").unwrap();
        assert!(secret.starts_with("jkbk_"));
        assert_eq!(rec.project_id, "proj");
        assert_eq!(rec.tenant_id, "tenantA");
        // Correct secret resolves the record (O(1) fingerprint lookup); it carries the owner
        // binding the mint path re-checks (P0-AUTH-3).
        let found = store.lookup_issuer_key_by_secret(&secret).unwrap().unwrap();
        assert_eq!(found.key_id, rec.key_id);
        assert_eq!(found.tenant_id, "tenantA");
        // A wrong / unknown secret resolves to nothing (fail-closed).
        assert!(
            store
                .lookup_issuer_key_by_secret("jkbk_not-a-real-secret")
                .unwrap()
                .is_none()
        );
        // Listed, then scoped-revoked; after revoke the secret no longer resolves.
        assert_eq!(store.list_issuer_keys("proj").unwrap().len(), 1);
        assert!(store.delete_issuer_key("proj", &rec.key_id).unwrap());
        assert!(
            store
                .lookup_issuer_key_by_secret(&secret)
                .unwrap()
                .is_none()
        );
        assert_eq!(store.list_issuer_keys("proj").unwrap().len(), 0);
        // Revoking a non-existent id is a no-op false (not an error).
        assert!(!store.delete_issuer_key("proj", "JKBK00").unwrap());
    }

    #[test]
    fn issuer_key_cap_and_teardown_purge_is_project_scoped() {
        let (store, _p) = tmp_db();
        for i in 0..Store::MAX_AUTH_ISSUER_KEYS_PER_PROJECT {
            store
                .create_issuer_key("proj", "t", &format!("k{i}"))
                .unwrap();
        }
        // Cap enforced.
        assert!(store.create_issuer_key("proj", "t", "over").is_err());
        // A second project is unaffected by the first's cap or teardown.
        let (_r, other_secret) = store.create_issuer_key("proj2", "t", "x").unwrap();

        // Teardown purges ONLY the target project's keys + signing key.
        store.ensure_signing_key("proj", 1).unwrap();
        let removed = store.delete_all_issuer_keys("proj").unwrap();
        assert_eq!(removed, Store::MAX_AUTH_ISSUER_KEYS_PER_PROJECT);
        assert_eq!(store.count_issuer_keys("proj").unwrap(), 0);
        store.delete_signing_key("proj").unwrap();
        assert!(store.get_signing_state("proj").unwrap().is_none());
        // proj2's credential still resolves.
        assert!(
            store
                .lookup_issuer_key_by_secret(&other_secret)
                .unwrap()
                .is_some()
        );
        assert_eq!(store.count_issuer_keys("proj2").unwrap(), 1);
    }

    #[test]
    fn tenant_quota_and_warm_usage_roundtrip() {
        let (store, path) = tmp_db();
        // Default when no override; no override recorded yet.
        assert_eq!(
            store.get_tenant_quota("t1").unwrap().warm_vm_max,
            DEFAULT_TENANT_QUOTA.warm_vm_max
        );
        assert!(store.get_tenant_quota_override("t1").unwrap().is_none());
        // An override persists and is isolated to that tenant.
        store
            .set_tenant_quota(
                "t1",
                &TenantQuotaLimits {
                    warm_vm_max: 40,
                    warm_relay_max: 500,
                },
            )
            .unwrap();
        assert_eq!(store.get_tenant_quota("t1").unwrap().warm_vm_max, 40);
        assert_eq!(store.get_tenant_quota("t1").unwrap().warm_relay_max, 500);
        assert!(store.get_tenant_quota_override("t1").unwrap().is_some());
        assert_eq!(
            store.get_tenant_quota("t2").unwrap().warm_vm_max,
            DEFAULT_TENANT_QUOTA.warm_vm_max
        );
        // Removing the override reverts to the default.
        assert!(store.remove_tenant_quota("t1").unwrap());
        assert_eq!(
            store.get_tenant_quota("t1").unwrap().warm_vm_max,
            DEFAULT_TENANT_QUOTA.warm_vm_max
        );

        // Warm-seconds accrue additively into the hour bucket and month-to-date.
        let hour = 1_000_000u64 / 3600 * 3600;
        store.add_warm_usage("p", hour, 60).unwrap();
        store.add_warm_usage("p", hour, 30).unwrap();
        assert_eq!(store.sum_month_to_date("p", hour).unwrap().warm_seconds, 90);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn delete_all_secrets_purges_only_the_target_project() {
        let (store, path) = tmp_db();
        store
            .set_secret("forumall", "DOMAIN", "forumall.jkbase.app")
            .unwrap();
        store.set_secret("forumall", "DATA_DIR", "/data").unwrap();
        // A slug that shares a prefix must NOT be swept (the ':' separator is exact).
        store.set_secret("forumall2", "OTHER", "keep").unwrap();
        store.set_secret("other", "X", "keep").unwrap();

        let removed = store.delete_all_secrets("forumall").unwrap();
        assert_eq!(removed, 2);
        assert!(store.list_secrets("forumall").unwrap().is_empty());
        assert_eq!(
            store.list_secrets("forumall2").unwrap().len(),
            1,
            "prefix boundary"
        );
        assert_eq!(store.list_secrets("other").unwrap().len(), 1);
        // Idempotent.
        assert_eq!(store.delete_all_secrets("forumall").unwrap(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn access_keys_issue_lookup_and_scope_to_project() {
        let (store, path) = tmp_db();
        let a = store.create_access_key("proj-a", "tenant-a", "ci").unwrap();
        let b = store.create_access_key("proj-b", "tenant-b", "").unwrap();
        // Issued ids are unique, AKIA-shaped, and `/`-free (SigV4 Credential safe).
        assert_ne!(a.access_key_id, b.access_key_id);
        assert!(a.access_key_id.starts_with("JKBA") && !a.access_key_id.contains('/'));
        assert!(!a.secret_key.is_empty() && a.secret_key != b.secret_key);

        // O(1) reverse lookup resolves the owning project + secret.
        let got = store.lookup_access_key(&a.access_key_id).unwrap().unwrap();
        assert_eq!(got.project_id, "proj-a");
        assert_eq!(got.secret_key, a.secret_key);
        assert!(
            store
                .lookup_access_key("JKBADEADBEEF00000000")
                .unwrap()
                .is_none()
        );

        // List is per-project.
        assert_eq!(store.list_access_keys("proj-a").unwrap().len(), 1);
        assert_eq!(store.list_access_keys("proj-b").unwrap().len(), 1);

        // A tenant can't revoke another project's key by guessing the id.
        assert!(!store.delete_access_key("proj-b", &a.access_key_id).unwrap());
        assert!(store.lookup_access_key(&a.access_key_id).unwrap().is_some());
        // The owning project can.
        assert!(store.delete_access_key("proj-a", &a.access_key_id).unwrap());
        assert!(store.lookup_access_key(&a.access_key_id).unwrap().is_none());
        assert!(store.list_access_keys("proj-a").unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_access_keys_mint_lookup_verify_and_scope() {
        let (store, path) = tmp_db();
        let (a, a_secret) = store
            .create_db_access_key("proj-a", "tenant-a", "ci")
            .unwrap();
        let (b, b_secret) = store
            .create_db_access_key("proj-b", "tenant-b", "")
            .unwrap();
        // Distinct JKBD-prefixed akids; the 240-bit secrets are unique and jkbd_-tagged.
        assert_ne!(a.access_key_id, b.access_key_id);
        assert!(a.access_key_id.starts_with("JKBD"));
        assert!(a_secret.starts_with("jkbd_") && a_secret != b_secret);

        // The record persists ONLY a fingerprint — never the secret ([R4]).
        assert_eq!(a.token_fingerprint, auth::token_fingerprint(&a_secret));
        assert_ne!(a.token_fingerprint, a_secret);

        // O(1) lookup resolves the owner; verify_secret is a const-time fingerprint match.
        let got = store
            .lookup_db_access_key(&a.access_key_id)
            .unwrap()
            .unwrap();
        assert_eq!(got.project_id, "proj-a");
        assert_eq!(got.tenant_id, "tenant-a");
        assert!(got.verify_secret(&a_secret));
        assert!(!got.verify_secret(&b_secret));
        assert!(!got.verify_secret("jkbd_wrong"));
        assert!(
            store
                .lookup_db_access_key("JKBDDEADBEEF00000000")
                .unwrap()
                .is_none()
        );

        // List + revoke are per-project (a tenant can't revoke another project's key).
        assert_eq!(store.list_db_access_keys("proj-a").unwrap().len(), 1);
        assert!(
            !store
                .delete_db_access_key("proj-b", &a.access_key_id)
                .unwrap()
        );
        assert!(
            store
                .lookup_db_access_key(&a.access_key_id)
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .delete_db_access_key("proj-a", &a.access_key_id)
                .unwrap()
        );
        assert!(
            store
                .lookup_db_access_key(&a.access_key_id)
                .unwrap()
                .is_none()
        );
        assert!(store.list_db_access_keys("proj-a").unwrap().is_empty());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_and_s3_keyspaces_never_cross_resolve() {
        let (store, path) = tmp_db();
        let s3 = store.create_access_key("proj", "t", "s3").unwrap();
        let (db, _db_secret) = store.create_db_access_key("proj", "t", "db").unwrap();

        // [R2]: an S3 key id must NOT resolve on the DB path, and a DB key id must NOT
        // resolve on the S3 path — separate tables, not a shared scope flag that's one
        // default-value bug from cross-streaming.
        assert!(
            store
                .lookup_db_access_key(&s3.access_key_id)
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .lookup_access_key(&db.access_key_id)
                .unwrap()
                .is_none()
        );

        // Each keyspace lists only its own kind.
        assert_eq!(store.list_access_keys("proj").unwrap().len(), 1);
        assert_eq!(store.list_db_access_keys("proj").unwrap().len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_access_key_cap_enforced_per_project() {
        let (store, path) = tmp_db();
        for i in 0..Store::MAX_DB_ACCESS_KEYS_PER_PROJECT {
            store
                .create_db_access_key("proj-a", "t1", &format!("k{i}"))
                .unwrap();
        }
        assert!(
            store
                .create_db_access_key("proj-a", "t1", "overflow")
                .is_err()
        );
        assert_eq!(
            store.count_db_access_keys("proj-a").unwrap(),
            Store::MAX_DB_ACCESS_KEYS_PER_PROJECT
        );
        // A different project is unaffected by another's full cap.
        assert!(store.create_db_access_key("proj-b", "t2", "ok").is_ok());

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_splice_secret_set_get_overwrite_delete() {
        let (store, path) = tmp_db();
        assert_eq!(store.get_db_splice_secret("p").unwrap(), None);
        store.set_db_splice_secret("p", "s3cr3t-1").unwrap();
        assert_eq!(
            store.get_db_splice_secret("p").unwrap().as_deref(),
            Some("s3cr3t-1")
        );
        // Overwrite (a fresh secret each deploy).
        store.set_db_splice_secret("p", "s3cr3t-2").unwrap();
        assert_eq!(
            store.get_db_splice_secret("p").unwrap().as_deref(),
            Some("s3cr3t-2")
        );
        // Scoped to the project.
        assert_eq!(store.get_db_splice_secret("q").unwrap(), None);
        store.delete_db_splice_secret("p").unwrap();
        assert_eq!(store.get_db_splice_secret("p").unwrap(), None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_admin_token_mint_get_overwrite_delete_and_scope() {
        let (store, path) = tmp_db();
        assert_eq!(store.get_db_admin_token("p").unwrap(), None);
        let t1 = store.mint_db_admin_token("p").unwrap();
        assert!(t1.starts_with("jkba_"));
        assert_eq!(
            store.get_db_admin_token("p").unwrap().as_deref(),
            Some(t1.as_str())
        );
        // Rotates on each deploy (fresh value).
        let t2 = store.mint_db_admin_token("p").unwrap();
        assert_ne!(t1, t2);
        assert_eq!(
            store.get_db_admin_token("p").unwrap().as_deref(),
            Some(t2.as_str())
        );
        // Scoped to the project; purged on teardown.
        assert_eq!(store.get_db_admin_token("q").unwrap(), None);
        store.delete_db_admin_token("p").unwrap();
        assert_eq!(store.get_db_admin_token("p").unwrap(), None);
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_backup_catalog_two_phase_scope_and_teardown() {
        let (store, path) = tmp_db();
        // A pending backup for proj-a, and one for a same-prefix slug proj-a2.
        let a = store
            .create_db_backup("proj-a", "t-a", "bkp_1_aa", "proj-a/bkp_1_aa.tar")
            .unwrap();
        assert_eq!(a.status, BackupStatus::Pending);
        assert_eq!(a.size_bytes, 0);
        let keep = store
            .create_db_backup("proj-a2", "t-a2", "bkp_9_zz", "proj-a2/bkp_9_zz.tar")
            .unwrap();

        // Cross-project resolution is refused ([RB6]): the id only resolves under its project.
        assert!(store.get_db_backup("proj-a", "bkp_9_zz").unwrap().is_none());
        assert!(
            store
                .get_db_backup("proj-a2", "bkp_9_zz")
                .unwrap()
                .is_some()
        );

        // Two-phase: flip to Complete with size + summary.
        store
            .set_db_backup_status("proj-a", "bkp_1_aa", BackupStatus::Complete, 4096, "2 ssts")
            .unwrap();
        let done = store.get_db_backup("proj-a", "bkp_1_aa").unwrap().unwrap();
        assert_eq!(done.status, BackupStatus::Complete);
        assert_eq!(done.size_bytes, 4096);
        assert_eq!(done.manifest_summary, "2 ssts");

        // A status update scoped to the wrong project is a no-op (doesn't touch the row).
        store
            .set_db_backup_status("proj-a2", "bkp_1_aa", BackupStatus::Failed, 0, "")
            .unwrap();
        assert_eq!(
            store
                .get_db_backup("proj-a", "bkp_1_aa")
                .unwrap()
                .unwrap()
                .status,
            BackupStatus::Complete
        );

        // Teardown purges only the target project (':' boundary is exact) and returns the rows.
        let removed = store.delete_all_db_backups("proj-a").unwrap();
        assert_eq!(removed.len(), 1);
        assert_eq!(removed[0].object_key, "proj-a/bkp_1_aa.tar");
        assert!(store.list_db_backups("proj-a").unwrap().is_empty());
        assert!(
            store
                .get_db_backup("proj-a2", &keep.backup_id)
                .unwrap()
                .is_some(),
            "prefix boundary: proj-a2 must survive"
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn db_backup_cap_enforced_per_project() {
        let (store, path) = tmp_db();
        for i in 0..Store::MAX_DB_BACKUPS_PER_PROJECT {
            store
                .create_db_backup(
                    "capproj",
                    "t",
                    &format!("bkp_{i}_x"),
                    &format!("capproj/{i}.tar"),
                )
                .unwrap();
        }
        assert!(
            store
                .create_db_backup("capproj", "t", "bkp_over_x", "capproj/over.tar")
                .is_err()
        );
        // A different project is unaffected.
        assert!(
            store
                .create_db_backup("other", "t", "bkp_ok_x", "other/ok.tar")
                .is_ok()
        );
        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn delete_all_db_access_keys_purges_only_the_target_project() {
        let (store, path) = tmp_db();
        let (k1, _) = store.create_db_access_key("forumall", "t1", "a").unwrap();
        let _ = store.create_db_access_key("forumall", "t1", "b").unwrap();
        // Prefix boundary: a same-prefix slug must NOT be swept (':' separator is exact).
        let keep = store
            .create_db_access_key("forumall2", "t2", "c")
            .unwrap()
            .0;

        let removed = store.delete_all_db_access_keys("forumall").unwrap();
        assert_eq!(removed, 2);
        assert!(
            store
                .lookup_db_access_key(&k1.access_key_id)
                .unwrap()
                .is_none()
        );
        assert!(store.list_db_access_keys("forumall").unwrap().is_empty());
        assert!(
            store
                .lookup_db_access_key(&keep.access_key_id)
                .unwrap()
                .is_some(),
            "prefix boundary: forumall2 must survive"
        );
        // Idempotent.
        assert_eq!(store.delete_all_db_access_keys("forumall").unwrap(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn delete_all_access_keys_purges_only_the_target_project() {
        let (store, path) = tmp_db();
        let k1 = store.create_access_key("forumall", "t1", "a").unwrap();
        let _k2 = store.create_access_key("forumall", "t1", "b").unwrap();
        // A slug that shares a prefix must NOT be swept (the ':' separator is exact).
        let keep = store.create_access_key("forumall2", "t2", "c").unwrap();

        let removed = store.delete_all_access_keys("forumall").unwrap();
        assert_eq!(removed, 2);
        assert!(store.list_access_keys("forumall").unwrap().is_empty());
        // Primary records are gone too (not just the index) — no orphaned secrets.
        assert!(
            store
                .lookup_access_key(&k1.access_key_id)
                .unwrap()
                .is_none()
        );
        // Prefix boundary: forumall2's key survives and still resolves.
        assert_eq!(
            store.list_access_keys("forumall2").unwrap().len(),
            1,
            "prefix boundary"
        );
        assert!(
            store
                .lookup_access_key(&keep.access_key_id)
                .unwrap()
                .is_some()
        );
        // Idempotent.
        assert_eq!(store.delete_all_access_keys("forumall").unwrap(), 0);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn binding_key_is_invisible_uncapped_rotated_and_purged() {
        let (store, path) = tmp_db();
        // Fill the project to the user-key cap; the binding key must NOT count against it.
        for i in 0..Store::MAX_ACCESS_KEYS_PER_PROJECT {
            store
                .create_access_key("p", "t1", &format!("k{i}"))
                .unwrap();
        }
        let b1 = store.mint_binding_key("p", "t1").unwrap();
        assert_eq!(b1.access_key_id, Store::binding_access_key_id("p"));
        // Resolvable by the SigV4 path…
        assert!(
            store
                .lookup_access_key(&b1.access_key_id)
                .unwrap()
                .is_some()
        );
        // …but invisible to the user key list (not in the per-project index).
        assert!(
            store
                .list_access_keys("p")
                .unwrap()
                .iter()
                .all(|k| k.access_key_id != b1.access_key_id)
        );
        assert_eq!(
            store.list_access_keys("p").unwrap().len(),
            Store::MAX_ACCESS_KEYS_PER_PROJECT
        );

        // Re-mint rotates the SECRET under the stable id (one entry, fresh secret).
        let b2 = store.mint_binding_key("p", "t1").unwrap();
        assert_eq!(b1.access_key_id, b2.access_key_id);
        assert_ne!(
            b1.secret_key, b2.secret_key,
            "deploy re-mint rotates the secret"
        );

        // Teardown purges it (by stable id) along with the user keys.
        store.delete_all_access_keys("p").unwrap();
        assert!(
            store
                .lookup_access_key(&b1.access_key_id)
                .unwrap()
                .is_none(),
            "binding key purged on teardown"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn access_key_cap_enforced_per_project() {
        let (store, path) = tmp_db();
        // Fill up to the cap for proj-a.
        for i in 0..Store::MAX_ACCESS_KEYS_PER_PROJECT {
            store
                .create_access_key("proj-a", "t1", &format!("key-{i}"))
                .unwrap_or_else(|e| panic!("key {i} should succeed: {e}"));
        }
        assert_eq!(
            store.count_access_keys("proj-a").unwrap(),
            Store::MAX_ACCESS_KEYS_PER_PROJECT
        );
        // The next key must be rejected.
        let err = store
            .create_access_key("proj-a", "t1", "overflow")
            .unwrap_err();
        assert!(
            err.to_string().contains("access key limit reached"),
            "unexpected error: {err}"
        );
        // A different project is unaffected — it can still issue keys freely.
        store
            .create_access_key("proj-b", "t2", "first")
            .expect("proj-b should not be throttled by proj-a's cap");
        assert_eq!(store.count_access_keys("proj-b").unwrap(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn access_key_range_scan_isolates_projects() {
        let (store, path) = tmp_db();
        // proj-x and proj-x2 share a prefix; verify the range boundary is exact.
        store.create_access_key("proj-x", "t1", "a").unwrap();
        store.create_access_key("proj-x", "t1", "b").unwrap();
        store.create_access_key("proj-x2", "t2", "c").unwrap();

        // list_access_keys must see exactly this project's entries.
        assert_eq!(store.list_access_keys("proj-x").unwrap().len(), 2);
        assert_eq!(store.list_access_keys("proj-x2").unwrap().len(), 1);
        assert_eq!(store.count_access_keys("proj-x").unwrap(), 2);
        assert_eq!(store.count_access_keys("proj-x2").unwrap(), 1);

        // delete_all_access_keys must not sweep the sibling project.
        let removed = store.delete_all_access_keys("proj-x").unwrap();
        assert_eq!(removed, 2, "wrong removal count");
        assert!(store.list_access_keys("proj-x").unwrap().is_empty());
        assert_eq!(
            store.list_access_keys("proj-x2").unwrap().len(),
            1,
            "proj-x2 must not be swept by delete_all_access_keys(proj-x)"
        );

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn quota_limits_back_compat_missing_new_fields() {
        // A QuotaLimits JSON that was serialized before max_objects / max_buckets
        // existed must deserialize with those fields set to the platform defaults.
        let old_json =
            r#"{"storage_bytes_max":1,"bandwidth_bytes_per_month":2,"build_seconds_per_month":3}"#;
        let q: QuotaLimits = serde_json::from_str(old_json).unwrap();
        assert_eq!(q.storage_bytes_max, 1);
        assert_eq!(q.bandwidth_bytes_per_month, 2);
        assert_eq!(q.build_seconds_per_month, 3);
        assert_eq!(
            q.max_objects, DEFAULT_MAX_OBJECTS,
            "max_objects should default"
        );
        assert_eq!(
            q.max_buckets, DEFAULT_MAX_BUCKETS,
            "max_buckets should default"
        );
    }

    #[test]
    fn provenance_fields_are_backward_compatible() {
        // Records written before B2 deserialize with the new fields defaulted.
        let dm: DeploymentMeta =
            serde_json::from_str(r#"{"project_id":"p","version":3,"created_at":7}"#).unwrap();
        assert!(dm.layer_digests.is_empty());

        let ts: BuildTargetStatus =
            serde_json::from_str(r#"{"name":"web","kind":"server","phase":"succeeded"}"#).unwrap();
        assert!(ts.builder_digest.is_none());
        assert!(ts.cache_key.is_none());
        assert!(ts.source_commit.is_none());
        assert!(ts.duration_breakdown_ms.is_empty());
        assert!(!ts.cache_hit);

        let br: BuildRecord = serde_json::from_str(
            r#"{"project_id":"p","build_id":1,"phase":"queued","created_at":0,"updated_at":0}"#,
        )
        .unwrap();
        assert!(br.source_commit.is_none());

        // New values round-trip through JSON.
        let mut ts2 = ts.clone();
        ts2.builder_digest = Some("sha256:abc".into());
        ts2.duration_breakdown_ms.insert("compile".into(), 1200);
        let back: BuildTargetStatus =
            serde_json::from_str(&serde_json::to_string(&ts2).unwrap()).unwrap();
        assert_eq!(back.builder_digest.as_deref(), Some("sha256:abc"));
        assert_eq!(back.duration_breakdown_ms.get("compile"), Some(&1200));
    }

    #[test]
    fn build_usage_accumulates_and_sums_month_to_date() {
        let (store, _p) = tmp_db();
        let month_start = month_start_epoch(1_700_000_000);
        let h0 = month_start; // first hour of the month
        let h1 = month_start + 3600;
        // Two builds in different hours of the same month.
        store.add_build_usage("p", h0, 30).unwrap();
        store.add_build_usage("p", h0, 12).unwrap(); // same hour accumulates
        store.add_build_usage("p", h1, 8).unwrap();
        // A different project must not leak in.
        store.add_build_usage("other", h0, 999).unwrap();

        let mtd = store.sum_month_to_date("p", month_start).unwrap();
        assert_eq!(mtd.build_seconds, 50);
        // build_seconds is independent of runtime CPU jiffies.
        assert_eq!(mtd.cpu_jiffies, 0);

        // A build before the month boundary is excluded.
        store.add_build_usage("p", month_start - 3600, 100).unwrap();
        assert_eq!(
            store
                .sum_month_to_date("p", month_start)
                .unwrap()
                .build_seconds,
            50
        );
    }

    #[test]
    fn deployments_listed_newest_first_and_scoped_per_project() {
        let (store, path) = tmp_db();
        store.save_deployment(&meta("a", 1)).unwrap();
        store.save_deployment(&meta("a", 2)).unwrap();
        store.save_deployment(&meta("a", 10)).unwrap();
        store.save_deployment(&meta("b", 5)).unwrap();

        let a = store.list_deployments("a").unwrap();
        assert_eq!(
            a.iter().map(|d| d.version).collect::<Vec<_>>(),
            vec![10, 2, 1],
            "newest version first"
        );
        let b = store.list_deployments("b").unwrap();
        assert_eq!(b.len(), 1, "other project's deployments excluded");
        assert_eq!(b[0].version, 5);

        assert_eq!(store.get_deployment("a", 2).unwrap().unwrap().version, 2);
        assert!(store.get_deployment("a", 99).unwrap().is_none());

        assert!(store.remove_deployment("a", 2).unwrap());
        assert_eq!(
            store
                .list_deployments("a")
                .unwrap()
                .iter()
                .map(|d| d.version)
                .collect::<Vec<_>>(),
            vec![10, 1]
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn schedules_scoped_per_project_with_last_run_rmw() {
        let (store, path) = tmp_db();
        let rec = |p: &str, f: &str| ScheduleRecord {
            project_id: p.to_string(),
            function: f.to_string(),
            cron: "*/5 * * * *".to_string(),
            last_run: None,
        };
        store.save_schedule(&rec("a", "f1")).unwrap();
        store.save_schedule(&rec("a", "f2")).unwrap();
        store.save_schedule(&rec("b", "f1")).unwrap();

        let mut a: Vec<_> = store
            .list_schedules_for_project("a")
            .unwrap()
            .into_iter()
            .map(|s| s.function)
            .collect();
        a.sort();
        assert_eq!(a, vec!["f1", "f2"], "prefix-scoped to project a");
        assert_eq!(store.list_schedules().unwrap().len(), 3, "all projects");

        store.update_schedule_last_run("a", "f1", 123).unwrap();
        let f1 = store
            .list_schedules_for_project("a")
            .unwrap()
            .into_iter()
            .find(|s| s.function == "f1")
            .unwrap();
        assert_eq!(f1.last_run, Some(123), "last_run advanced");
        assert_eq!(f1.cron, "*/5 * * * *", "cron preserved across rmw");

        // RMW on a missing schedule is a silent no-op.
        store.update_schedule_last_run("a", "ghost", 1).unwrap();

        assert!(store.remove_schedule("a", "f1").unwrap());
        assert!(
            !store.remove_schedule("a", "f1").unwrap(),
            "second remove false"
        );
        assert_eq!(store.list_schedules_for_project("a").unwrap().len(), 1);
        assert_eq!(
            store.list_schedules_for_project("b").unwrap().len(),
            1,
            "b intact"
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn usage_accumulates_and_sums_month_to_date() {
        let (store, path) = tmp_db();
        let h0: u64 = 1_700_000_000 / 3600 * 3600; // some hour
        let h1 = h0 + 3600;
        // two samples in h0, one in h1
        store.add_usage("a", h0, 10, 100, 200, 1000, 60).unwrap();
        store.add_usage("a", h0, 5, 50, 60, 1000, 60).unwrap();
        store.add_usage("a", h1, 7, 70, 80, 2000, 60).unwrap();
        store.add_usage("b", h0, 99, 9, 9, 9, 60).unwrap();

        let buckets = store.list_usage_for_project("a", 0, u64::MAX).unwrap();
        assert_eq!(buckets.len(), 2, "two hour buckets for a");
        assert_eq!(buckets[0].cpu_jiffies, 15, "h0 accumulated 10+5");
        assert_eq!(buckets[0].sample_count, 2);
        assert_eq!(buckets[0].storage_bytes_last, 1000);

        // month-to-date from h0 sums both hours; storage = latest gauge (h1)
        let mtd = store.sum_month_to_date("a", h0).unwrap();
        assert_eq!(mtd.cpu_jiffies, 22);
        assert_eq!(mtd.rx_bytes, 220);
        assert_eq!(mtd.tx_bytes, 340);
        assert_eq!(mtd.storage_bytes, 2000, "latest gauge, not summed");

        // window starting after h0 excludes it
        let mtd_h1 = store.sum_month_to_date("a", h1).unwrap();
        assert_eq!(mtd_h1.cpu_jiffies, 7);

        // prune older than h1 drops h0 only (for all projects)
        let pruned = store.prune_usage(h1).unwrap();
        assert_eq!(pruned, 2, "a@h0 and b@h0");
        assert_eq!(
            store
                .list_usage_for_project("a", 0, u64::MAX)
                .unwrap()
                .len(),
            1
        );

        // purge drops the rest for a, leaves nothing
        store.purge_usage("a").unwrap();
        assert!(
            store
                .list_usage_for_project("a", 0, u64::MAX)
                .unwrap()
                .is_empty()
        );

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn quota_default_override_and_status() {
        let (store, path) = tmp_db();
        // default when no override
        assert_eq!(
            store.get_quota("p").unwrap().storage_bytes_max,
            DEFAULT_QUOTA.storage_bytes_max
        );
        assert!(store.get_quota_override("p").unwrap().is_none());

        store
            .set_quota(
                "p",
                &QuotaLimits {
                    storage_bytes_max: 123,
                    bandwidth_bytes_per_month: 456,
                    build_seconds_per_month: 789,
                    max_objects: DEFAULT_MAX_OBJECTS,
                    max_buckets: DEFAULT_MAX_BUCKETS,
                },
            )
            .unwrap();
        assert_eq!(store.get_quota("p").unwrap().storage_bytes_max, 123);
        assert_eq!(store.get_quota("p").unwrap().build_seconds_per_month, 789);
        assert!(store.get_quota_override("p").unwrap().is_some());
        assert!(store.remove_quota("p").unwrap());
        assert_eq!(
            store.get_quota("p").unwrap().bandwidth_bytes_per_month,
            DEFAULT_QUOTA.bandwidth_bytes_per_month
        );

        // status round-trip
        assert!(store.get_quota_status("p").unwrap().is_none());
        store
            .save_quota_status(&QuotaStatus {
                project_id: "p".to_string(),
                bandwidth_blocked: true,
                blocked_reason: Some("cap".to_string()),
                blocked_at: 1,
                blocked_month: month_start_epoch(1_700_000_000),
            })
            .unwrap();
        assert!(
            store
                .get_quota_status("p")
                .unwrap()
                .unwrap()
                .bandwidth_blocked
        );
        assert!(store.remove_quota_status("p").unwrap());

        let _ = std::fs::remove_file(&path);
    }

    fn domain(host: &str, project: &str, tenant: &str, status: DomainStatus) -> DomainRecord {
        DomainRecord {
            host: host.to_string(),
            project_id: project.to_string(),
            tenant_id: tenant.to_string(),
            site: None,
            kind: if host.contains('.') {
                DomainKind::Custom
            } else {
                DomainKind::Subdomain
            },
            status,
            token: "tok".to_string(),
            created_at: 0,
        }
    }

    #[test]
    fn claim_is_atomic_and_unique() {
        let (store, path) = tmp_db();
        assert!(
            store
                .claim_domain(&domain("docs", "a", "t1", DomainStatus::Active))
                .unwrap()
        );
        // Second claim of the same host fails, even for a different tenant.
        assert!(
            !store
                .claim_domain(&domain("docs", "b", "t2", DomainStatus::Active))
                .unwrap()
        );
        assert_eq!(store.get_domain("docs").unwrap().unwrap().project_id, "a");

        // Reserved labels are never available; free labels are.
        assert!(!store.host_key_available("api").unwrap());
        assert!(!store.host_key_available("docs").unwrap()); // taken
        assert!(store.host_key_available("blog").unwrap());

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn active_filter_and_purge_per_project() {
        let (store, path) = tmp_db();
        store
            .claim_domain(&domain("blog", "a", "t1", DomainStatus::Active))
            .unwrap();
        store
            .claim_domain(&domain(
                "docs.example.com",
                "a",
                "t1",
                DomainStatus::Pending,
            ))
            .unwrap();
        store
            .claim_domain(&domain("other", "b", "t2", DomainStatus::Active))
            .unwrap();

        let all_a = store.list_domains_for_project("a").unwrap();
        assert_eq!(all_a.len(), 2);
        let active_a = store.list_active_domains_for_project("a").unwrap();
        assert_eq!(active_a.len(), 1);
        assert_eq!(active_a[0].host, "blog");

        // Purge project a's domains (delete_project path).
        for d in store.list_domains_for_project("a").unwrap() {
            store.remove_domain(&d.host).unwrap();
        }
        assert!(store.list_domains_for_project("a").unwrap().is_empty());
        assert!(store.get_domain("other").unwrap().is_some()); // b untouched

        let _ = std::fs::remove_file(&path);
    }

    #[test]
    fn host_crud_and_heartbeat_rmw() {
        let (store, path) = tmp_db();
        let h = HostRecord {
            host_id: "host-a".into(),
            region: "ca-east".into(),
            public_addr: Some("10.0.0.1:9090".into()),
            last_heartbeat: 0,
            cpu_template_id: None,
            kernel_id: Some("vmlinux-6.12".into()),
            capacity: HostCapacity {
                vcpus: 16,
                mem_mib: 131072,
                max_vms: 64,
            },
        };
        store.save_host(&h).unwrap();
        store
            .save_host(&HostRecord {
                host_id: "host-b".into(),
                region: "eu-west".into(),
                ..h.clone()
            })
            .unwrap();
        assert_eq!(store.list_hosts().unwrap().len(), 2);
        assert_eq!(store.get_host("host-a").unwrap().unwrap().region, "ca-east");
        assert!(store.get_host("ghost").unwrap().is_none());

        // RMW advances only last_heartbeat, preserving the rest.
        store.touch_host_heartbeat("host-a", 12345).unwrap();
        let a = store.get_host("host-a").unwrap().unwrap();
        assert_eq!(a.last_heartbeat, 12345);
        assert_eq!(a.capacity.vcpus, 16, "capacity preserved across rmw");
        assert_eq!(a.kernel_id.as_deref(), Some("vmlinux-6.12"));
        // RMW on a missing host is a silent no-op.
        store.touch_host_heartbeat("ghost", 1).unwrap();
        assert!(store.get_host("ghost").unwrap().is_none());

        assert!(store.remove_host("host-a").unwrap());
        assert!(!store.remove_host("host-a").unwrap(), "second remove false");
        assert_eq!(store.list_hosts().unwrap().len(), 1);

        let _ = std::fs::remove_file(path);
    }

    #[test]
    fn vm_allocation_new_fields_back_compat() {
        // An allocation persisted before host_id/placement_epoch existed must
        // deserialize with those fields defaulted (empty host, epoch 0).
        let old = r#"{"project_id":"p","ip":"172.16.0.2","tap_device":"jktap-p","mac":"AA:BB:CC:00:00:02"}"#;
        let a: VmAllocation = serde_json::from_str(old).unwrap();
        assert_eq!(a.project_id, "p");
        assert_eq!(a.host_id, "", "host_id defaults empty");
        assert_eq!(a.placement_epoch, 0, "placement_epoch defaults 0");
        // New values round-trip through JSON.
        let mut a2 = a.clone();
        a2.host_id = "host-a".into();
        a2.placement_epoch = 7;
        let back: VmAllocation =
            serde_json::from_str(&serde_json::to_string(&a2).unwrap()).unwrap();
        assert_eq!(back.host_id, "host-a");
        assert_eq!(back.placement_epoch, 7);
    }

    #[test]
    fn host_record_back_compat_missing_optionals() {
        // A minimal host record (only the required fields) deserializes with the
        // optional/HA fields defaulted — so a record written by an earlier P0 build
        // (before later phases add fields) still loads.
        let json = r#"{"host_id":"h","region":"r"}"#;
        let h: HostRecord = serde_json::from_str(json).unwrap();
        assert_eq!(h.host_id, "h");
        assert!(h.public_addr.is_none());
        assert_eq!(h.last_heartbeat, 0);
        assert!(h.cpu_template_id.is_none());
        assert!(h.kernel_id.is_none());
        assert_eq!(h.capacity.vcpus, 0);
        assert_eq!(h.capacity.mem_mib, 0);
    }
}
