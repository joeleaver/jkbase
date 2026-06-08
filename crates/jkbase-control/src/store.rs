use crate::auth::{self, ApiToken, Tenant};
use anyhow::{Context, Result};
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;

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
/// Per-project connected-repo trigger credentials (build · D): the git-push
/// token fingerprint, bound to the owning tenant. Kept out of the app-`SECRETS`
/// table (those are tenant env vars) so the two never leak into each other.
const REPO_TRIGGERS: TableDefinition<&str, &[u8]> = TableDefinition::new("repo_triggers");

/// Subdomain labels reserved for the platform; tenants cannot claim them as new
/// hostnames (existing projects with these ids are grandfathered at backfill).
pub const RESERVED_LABELS: &[&str] = &["api", "www", "console"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ProjectState {
    Active,
    Stopped,
    Hibernated,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotMeta {
    pub project_id: String,
    pub snapshot_path: String,
    pub mem_file_path: String,
    pub created_at: u64,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub project_id: String,
    pub key: String,
    pub value: String,
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
}

const DEFAULT_BUILD_SECONDS_PER_MONTH: u64 = 200 * 60; // 200 build-minutes/month
fn default_build_seconds_per_month() -> u64 {
    DEFAULT_BUILD_SECONDS_PER_MONTH
}

pub const DEFAULT_QUOTA: QuotaLimits = QuotaLimits {
    storage_bytes_max: 16 * 1024 * 1024 * 1024,        // 16 GiB
    bandwidth_bytes_per_month: 100 * 1024 * 1024 * 1024, // 100 GiB/month
    build_seconds_per_month: DEFAULT_BUILD_SECONDS_PER_MONTH,
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
}

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
    pub fn sum_month_to_date(&self, project_id: &str, month_start_epoch: u64) -> Result<MonthToDate> {
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
        Ok(self.get_quota_override(project_id)?.unwrap_or(DEFAULT_QUOTA))
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
                && let Some(tenant_data) = tenants_table.get(api_token.tenant_id.as_str())? {
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
            store.sum_month_to_date("p", month_start).unwrap().build_seconds,
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
            store.list_deployments("a").unwrap().iter().map(|d| d.version).collect::<Vec<_>>(),
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
        assert!(!store.remove_schedule("a", "f1").unwrap(), "second remove false");
        assert_eq!(store.list_schedules_for_project("a").unwrap().len(), 1);
        assert_eq!(store.list_schedules_for_project("b").unwrap().len(), 1, "b intact");

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
        assert_eq!(store.list_usage_for_project("a", 0, u64::MAX).unwrap().len(), 1);

        // purge drops the rest for a, leaves nothing
        store.purge_usage("a").unwrap();
        assert!(store.list_usage_for_project("a", 0, u64::MAX).unwrap().is_empty());

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
        assert!(store.get_quota_status("p").unwrap().unwrap().bandwidth_blocked);
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
        assert!(store
            .claim_domain(&domain("docs", "a", "t1", DomainStatus::Active))
            .unwrap());
        // Second claim of the same host fails, even for a different tenant.
        assert!(!store
            .claim_domain(&domain("docs", "b", "t2", DomainStatus::Active))
            .unwrap());
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
            .claim_domain(&domain("docs.example.com", "a", "t1", DomainStatus::Pending))
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
}
