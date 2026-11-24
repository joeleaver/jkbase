//! Managed-DB executors ([RB*] + console DB tools): the host side of every operation the
//! control plane drives against a project's in-VM rhypedb — backup PULL into the platform store,
//! restore PUSH, the nightly backup loop, and the synchronous console ops (query / schema /
//! status / the owner's `rewrite-covers` pass). All of them reach the DB the same way: wake the
//! VM serving it, then talk to its agent's eth0 `/_jkbase/db/*` seam with the per-deploy splice
//! secret. The DB stays loopback-only and the admin token never leaves the guest.

use super::*;

/// Hard cap on a backup tar the agent may relay + the host stages ([RB3]). The tar is roughly
/// the DB's on-disk size (bounded by the RWO data disk); this ceiling fails a runaway/garbage
/// stream fast, well before it could exhaust host disk under the concurrency bound below.
const MAX_DB_BACKUP_BYTES: u64 = 16 * 1024 * 1024 * 1024;
/// Retained COMPLETE backups per project (retention bound; the store cap
/// [`Store::MAX_DB_BACKUPS_PER_PROJECT`] is the backstop).
const DB_BACKUP_KEEP: usize = 14;
/// Retained Failed rows per project — enough for the nightly loop's failure backoff to see the
/// last failure time (so a persistently-failing project retries once per interval, not per tick),
/// and for the owner to see recent failures, without letting Failed rows wedge the cap.
const DB_BACKUP_FAILED_KEEP: usize = 3;
/// Nightly-loop cadence + the age at which a managed DB is due for an automatic backup.
const DB_BACKUP_TICK: Duration = Duration::from_secs(30 * 60);
const DB_BACKUP_INTERVAL_MS: u64 = 24 * 60 * 60 * 1000;
/// Max concurrent backup PULLS across the WHOLE host (on-demand AND nightly share this), so a
/// tenant spamming on-demand backups — or the nightly fan-out — can't stage many full-DB tars
/// into off-quota host disk at once (adversarial-review finding).
pub(crate) const DB_BACKUP_MAX_CONCURRENT: usize = 2;

/// Everything the backup/restore executors need. All handles are cheap Arc clones.
#[derive(Clone)]
pub(crate) struct DbBackupCtx {
    pub(crate) platform: Arc<Mutex<PlatformState>>,
    pub(crate) routing: jkbase_proxy::RoutingTable,
    pub(crate) domains: DomainMap,
    pub(crate) shipper: Arc<LogShipper>,
    pub(crate) store: Store,
    pub(crate) backups: Arc<db_backup_store::BackupStore>,
    /// Host-wide concurrency bound shared by on-demand + nightly backups.
    pub(crate) backup_sem: Arc<tokio::sync::Semaphore>,
    /// Per-project in-flight restore guard so two overlapping restores can't corrupt the shared
    /// staging dir (adversarial-review finding).
    pub(crate) restoring: Arc<std::sync::Mutex<HashSet<String>>>,
}

/// Client-side HTTP/1.1 `Upgrade` to `<vm_ip>:80{path}` presenting the reach-plane splice
/// secret (mirrors the proxy edge's `connect_agent`). On `101` returns the raw upgraded stream.
/// Used by the backup PULL and restore PUSH executors — the DB stays loopback-only, the agent
/// is the sole mediator.
pub(crate) async fn connect_agent_db_upgrade(
    vm_ip: &str,
    path: &str,
    splice_secret: &str,
    proto: &str,
) -> Result<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>> {
    use http_body_util::Full;
    use hyper::body::Bytes;
    let stream = tokio::net::TcpStream::connect((vm_ip, 80u16))
        .await
        .context("connect agent")?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("agent handshake")?;
    tokio::spawn(async move {
        let _ = conn.with_upgrades().await;
    });
    let req = hyper::Request::builder()
        .method("GET")
        .uri(path)
        .header("host", vm_ip)
        .header("connection", "upgrade")
        .header("upgrade", proto)
        .header("x-jkbase-db-secret", splice_secret)
        .body(Full::<Bytes>::new(Bytes::new()))
        .context("agent req build")?;
    let mut resp = sender.send_request(req).await.context("agent send")?;
    if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
        anyhow::bail!("agent refused {path} upgrade ({})", resp.status());
    }
    let upgraded = hyper::upgrade::on(&mut resp)
        .await
        .context("agent upgrade")?;
    Ok(hyper_util::rt::TokioIo::new(upgraded))
}

/// Pull a backup: wake the VM, relay the tar out of the agent, validate + store it, return
/// (size, manifest summary). The admin token never leaves the guest — the agent authorizes the
/// loopback `/admin/backup/stream` and relays only opaque tar bytes.
async fn do_db_backup(
    ctx: &DbBackupCtx,
    project_id: &str,
    backup_id: &str,
) -> Result<(u64, String)> {
    let secret = ctx
        .store
        .get_db_splice_secret(project_id)?
        .ok_or_else(|| anyhow::anyhow!("no reach-plane secret (managed DB not deployed?)"))?;
    let ip = wake_db_reach(
        project_id,
        ctx.platform.clone(),
        ctx.routing.clone(),
        ctx.domains.clone(),
        ctx.shipper.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("wake project: {e:?}"))?;
    let mut upgraded =
        connect_agent_db_upgrade(&ip, "/_jkbase/db/backup", &secret, "jkbase-db-backup").await?;
    let staged = ctx
        .backups
        .stage(project_id, backup_id, &mut upgraded, MAX_DB_BACKUP_BYTES)
        .await?;
    let size = staged.size_bytes;
    match ctx.backups.validate(&staged).await {
        Ok(summary) => {
            ctx.backups.commit(staged).await?;
            Ok((size, summary))
        }
        Err(e) => {
            ctx.backups.discard(staged).await;
            Err(e)
        }
    }
}

/// Max bytes the host buffers from the in-VM DB's HTTP response before relaying to the console.
/// The engine's query governor caps result ROWS; this bounds the host relay against a
/// pathological payload. Schema/status responses are tiny.
const MAX_DB_QUERY_RESP_BYTES: usize = 16 * 1024 * 1024;
/// Outer deadline on one console DB request (agent connect + engine round-trip). The engine
/// governor caps per-query wall-clock; this is the network-level backstop.
const DB_QUERY_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// Send one PLAIN (non-upgrade) request to the agent's eth0 DB-proxy seam and read the bounded
/// JSON response. The DB stays loopback-only; the agent forwards only to rhypedb's OPEN plane
/// (`/query|/schema|/status`, never `/admin/*`). Returns the engine's verbatim status + body.
async fn agent_db_request(
    vm_ip: &str,
    path: &str,
    method: &str,
    splice_secret: &str,
    body: Vec<u8>,
) -> Result<jkbase_control::api::DbQueryResult> {
    use http_body_util::{BodyExt, Full, Limited};
    use hyper::body::Bytes;
    let stream = tokio::net::TcpStream::connect((vm_ip, 80u16))
        .await
        .context("connect agent")?;
    let io = hyper_util::rt::TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
        .await
        .context("agent handshake")?;
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = hyper::Request::builder()
        .method(method)
        .uri(path)
        .header("host", vm_ip)
        .header("content-type", "application/json")
        .header("x-jkbase-db-secret", splice_secret)
        .body(Full::<Bytes>::new(Bytes::from(body)))
        .context("agent req build")?;
    let resp = sender.send_request(req).await.context("agent send")?;
    let status = resp.status().as_u16();
    let collected = Limited::new(resp.into_body(), MAX_DB_QUERY_RESP_BYTES)
        .collect()
        .await
        .map_err(|_| {
            anyhow::anyhow!("db response too large (> {MAX_DB_QUERY_RESP_BYTES} bytes)")
        })?;
    Ok(jkbase_control::api::DbQueryResult {
        status,
        body: collected.to_bytes().to_vec(),
    })
}

/// Everything the synchronous console DB ops need (wired to `state.db_query_callback`). All
/// handles are cheap Arc clones.
#[derive(Clone)]
pub(crate) struct DbQueryCtx {
    pub(crate) platform: Arc<Mutex<PlatformState>>,
    pub(crate) routing: jkbase_proxy::RoutingTable,
    pub(crate) domains: DomainMap,
    pub(crate) shipper: Arc<LogShipper>,
    pub(crate) store: Store,
    /// The reach-plane live-relay registry. A `rewrite-covers` pass holds one slot in it for its
    /// whole lifetime: `conn_count > 0` keeps the DB VM out of idle hibernation (the default idle
    /// timeout is far shorter than a big store's pass), and a project delete / graceful drain
    /// (`cancel_project` / `cancel_all`) aborts the host side of the pass.
    pub(crate) relays: Arc<jkbase_proxy::db_relay::DbRelayRegistry>,
    /// Projects with a `rewrite-covers` pass in flight on this host (per-project single-flight).
    pub(crate) rewriting: Arc<std::sync::Mutex<HashSet<String>>>,
}

/// Proxy one console DB op to the project's managed DB (wired to `state.db_query_callback`):
/// resolve the reach-plane splice secret, wake the VM, and forward to the agent's eth0 seam.
/// `Err(String)` is a transport/wake failure; the engine's own errors ride back in the `Ok`
/// result's status (e.g. 400 for a parse/governor error).
pub(crate) async fn do_db_query(
    ctx: DbQueryCtx,
    project_id: String,
    op: jkbase_control::api::DbQueryOp,
) -> Result<jkbase_control::api::DbQueryResult, String> {
    use jkbase_control::api::DbQueryOp;
    let (path, method, body): (&str, &str, Vec<u8>) = match &op {
        DbQueryOp::Query(q) => (
            "/_jkbase/db/query",
            "POST",
            serde_json::to_vec(&serde_json::json!({ "query": q })).unwrap_or_default(),
        ),
        DbQueryOp::Schema => ("/_jkbase/db/schema", "GET", Vec::new()),
        DbQueryOp::Status => ("/_jkbase/db/status", "GET", Vec::new()),
        DbQueryOp::RewriteCovers => return do_db_rewrite_covers(&ctx, &project_id).await,
    };
    let secret = db_splice_secret(&ctx.store, &project_id)?;
    let ip = wake_db_reach(
        &project_id,
        ctx.platform,
        ctx.routing,
        ctx.domains,
        ctx.shipper,
    )
    .await
    .map_err(|e| format!("wake project: {e:?}"))?;
    tokio::time::timeout(
        DB_QUERY_DEADLINE,
        agent_db_request(&ip, path, method, &secret, body),
    )
    .await
    .map_err(|_| "database request timed out".to_string())?
    .map_err(|e| format!("{e:#}"))
}

fn db_splice_secret(store: &Store, project_id: &str) -> Result<String, String> {
    store
        .get_db_splice_secret(project_id)
        .map_err(|e| e.to_string())?
        .ok_or_else(|| "no managed database deployed for this project".to_string())
}

/// Outer deadline on one `rewrite-covers` pass (wake + the whole engine pass). The engine works in
/// batches and is safe to interrupt, so on expiry the host just drops the agent connection: the
/// engine finishes or stops on its own and a rerun redoes only what is still stale. Long enough
/// for a large store, bounded so a wedged engine can't pin the keep-warm hold forever.
const DB_REWRITE_COVERS_DEADLINE: Duration = Duration::from_secs(60 * 60);
/// Synthetic akid for the keep-warm hold in the relay registry. Never a real DB key, so a key
/// revocation (`cancel_key`) never targets it; `cancel_project` / `cancel_all` still do.
const DB_ADMIN_HOLD_AKID: &str = "__db_admin_op__";

/// The owner's `rewrite-covers` pass ([`DbQueryOp::RewriteCovers`]). Bounded on every axis:
/// single-flight per project (a second call while one runs is a 409, before any wake), one
/// keep-warm hold in the relay registry registered BEFORE the wake (so a project delete during
/// the wake aborts it — [R5]), and [`DB_REWRITE_COVERS_DEADLINE`] over the whole thing. The
/// project's OWN splice secret + VM are the only target; the agent authorizes the hard-coded
/// admin call with the in-guest token.
///
/// [`DbQueryOp::RewriteCovers`]: jkbase_control::api::DbQueryOp::RewriteCovers
async fn do_db_rewrite_covers(
    ctx: &DbQueryCtx,
    project_id: &str,
) -> Result<jkbase_control::api::DbQueryResult, String> {
    let Some(_running) = RewriteInFlight::try_start(&ctx.rewriting, project_id) else {
        return Ok(json_result(
            409,
            "a rewrite-covers pass is already running for this project's database",
        ));
    };
    let secret = db_splice_secret(&ctx.store, project_id)?;
    let (_hold, cancel) = hold_db_vm_warm(&ctx.relays, project_id)?;
    let run = async {
        let ip = wake_db_reach(
            project_id,
            ctx.platform.clone(),
            ctx.routing.clone(),
            ctx.domains.clone(),
            ctx.shipper.clone(),
        )
        .await
        .map_err(|e| format!("wake project: {e:?}"))?;
        agent_db_request(
            &ip,
            "/_jkbase/db/rewrite-covers",
            "POST",
            &secret,
            Vec::new(),
        )
        .await
        .map_err(|e| format!("{e:#}"))
    };
    let res = tokio::select! {
        _ = cancel.cancelled() => {
            return Err("rewrite-covers aborted (project deleted or server shutting down); \
                        rerunning it is safe".to_string());
        }
        r = tokio::time::timeout(DB_REWRITE_COVERS_DEADLINE, run) => r.map_err(|_| {
            "rewrite-covers did not finish within the deadline; the database may still be \
             working on it. Rerunning is safe and redoes only what is still stale — check \
             `cover_peers_sound` in the database status first."
                .to_string()
        })??,
    };
    info!(project = %project_id, status = res.status, "managed-db rewrite-covers finished");
    Ok(rewrite_covers_result(res))
}

/// Map the agent's answer for the operator. The engine's own answer (200 with `ok` true/false +
/// its counters, or its error status) passes through verbatim. A 404 can only mean the VM's agent
/// has no such endpoint (a VM booted before this shipped) or no admin token baked — the host
/// presented the project's current splice secret — so say how to fix it instead of a bare 404.
fn rewrite_covers_result(
    res: jkbase_control::api::DbQueryResult,
) -> jkbase_control::api::DbQueryResult {
    if res.status == 404 {
        return json_result(
            409,
            "the project's database VM is running an older agent without rewrite-covers; \
             restart or redeploy the project, then retry",
        );
    }
    res
}

fn json_result(status: u16, error: &str) -> jkbase_control::api::DbQueryResult {
    jkbase_control::api::DbQueryResult {
        status,
        body: serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap_or_default(),
    }
}

/// Register the keep-warm hold for an admin op on `project_id`'s DB (keyed by the BASE project, so
/// it keeps a dedicated `{id}.db` VM warm too). No tenant (an owner-driven maintenance op must not
/// be refused by — or count against — the external reach warm-VM quota) and no per-project cap:
/// the hold is already bounded to one per project by the single-flight guard.
fn hold_db_vm_warm(
    relays: &Arc<jkbase_proxy::db_relay::DbRelayRegistry>,
    project_id: &str,
) -> Result<
    (
        jkbase_proxy::db_relay::RelayGuard,
        tokio_util::sync::CancellationToken,
    ),
    String,
> {
    relays
        .try_register(project_id, None, DB_ADMIN_HOLD_AKID, usize::MAX, 0, 0)
        .map_err(|r| format!("could not hold the database VM warm: {r:?}"))
}

/// RAII per-project single-flight slot for `rewrite-covers`; released on drop (any exit path).
struct RewriteInFlight {
    set: Arc<std::sync::Mutex<HashSet<String>>>,
    project_id: String,
}

impl RewriteInFlight {
    fn try_start(set: &Arc<std::sync::Mutex<HashSet<String>>>, project_id: &str) -> Option<Self> {
        let mut running = set.lock().unwrap_or_else(|p| p.into_inner());
        running.insert(project_id.to_string()).then(|| Self {
            set: set.clone(),
            project_id: project_id.to_string(),
        })
    }
}

impl Drop for RewriteInFlight {
    fn drop(&mut self) {
        self.set
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(&self.project_id);
    }
}

/// Run one backup end-to-end (spawned by the on-demand callback + the nightly loop): acquire the
/// host-wide concurrency permit, execute, record the catalog outcome, and prune the catalog —
/// on EITHER outcome, so failed backups can never wedge the per-project row cap
/// (adversarial-review finding).
pub(crate) async fn run_db_backup(ctx: DbBackupCtx, project_id: String, backup_id: String) {
    // Bound host-wide concurrent pulls (shared by on-demand + nightly). A closed semaphore never
    // happens (we never close it); on the impossible error, fail the backup rather than run
    // unbounded.
    let _permit = match ctx.backup_sem.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Failed,
                0,
                "",
            );
            return;
        }
    };
    match do_db_backup(&ctx, &project_id, &backup_id).await {
        Ok((size, summary)) => {
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Complete,
                size,
                &summary,
            );
            info!(project = %project_id, backup = %backup_id, size, "managed-db backup complete");
        }
        Err(e) => {
            warn!(project = %project_id, backup = %backup_id, error = %e, "managed-db backup failed");
            let _ = ctx.store.set_db_backup_status(
                &project_id,
                &backup_id,
                jkbase_control::store::BackupStatus::Failed,
                0,
                "",
            );
            let _ = ctx.backups.delete(&project_id, &backup_id).await;
        }
    }
    // Prune on EVERY outcome so a run of failures can't fill the per-project row cap and
    // permanently disable backups for the project.
    prune_db_backups(&ctx, &project_id).await;
}

/// Push a restore: resolve the (Complete) backup, wake the VM, and stream the tar to the agent,
/// which untars it in-guest and respawns rhypedb. Reads back the agent's `ok`/`err:` line.
async fn do_db_restore(ctx: &DbBackupCtx, project_id: &str, backup_id: &str) -> Result<()> {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    // Serialize restores per project: two overlapping restores share the same in-guest staging
    // paths and would corrupt each other (adversarial-review finding). RAII-remove on return.
    struct RestoreGuard(Arc<std::sync::Mutex<HashSet<String>>>, String);
    impl Drop for RestoreGuard {
        fn drop(&mut self) {
            self.0.lock().unwrap().remove(&self.1);
        }
    }
    {
        let mut set = ctx.restoring.lock().unwrap();
        if !set.insert(project_id.to_string()) {
            anyhow::bail!("a restore is already in progress for this project");
        }
    }
    let _guard = RestoreGuard(ctx.restoring.clone(), project_id.to_string());

    let backup = ctx
        .store
        .get_db_backup(project_id, backup_id)?
        .ok_or_else(|| anyhow::anyhow!("backup not found"))?;
    if backup.status != jkbase_control::store::BackupStatus::Complete {
        anyhow::bail!(
            "backup {backup_id} is not restorable (status {:?})",
            backup.status
        );
    }
    let secret = ctx
        .store
        .get_db_splice_secret(project_id)?
        .ok_or_else(|| anyhow::anyhow!("no reach-plane secret"))?;
    let ip = wake_db_reach(
        project_id,
        ctx.platform.clone(),
        ctx.routing.clone(),
        ctx.domains.clone(),
        ctx.shipper.clone(),
    )
    .await
    .map_err(|e| anyhow::anyhow!("wake project: {e:?}"))?;
    let mut tar = ctx.backups.open_read(project_id, backup_id).await?;
    let mut upgraded =
        connect_agent_db_upgrade(&ip, "/_jkbase/db/restore", &secret, "jkbase-db-restore").await?;
    tokio::io::copy(&mut tar, &mut upgraded)
        .await
        .context("stream backup to agent")?;
    // Half-close the write half → the agent sees a clean EOF for the tar, processes it, then
    // writes its status line back on the still-open read half.
    upgraded
        .shutdown()
        .await
        .context("half-close restore push")?;
    let mut status = String::new();
    upgraded
        .read_to_string(&mut status)
        .await
        .context("read restore status")?;
    let status = status.trim();
    if status == "ok" {
        Ok(())
    } else {
        anyhow::bail!(
            "agent restore: {}",
            if status.is_empty() {
                "no response"
            } else {
                status
            }
        )
    }
}

pub(crate) async fn run_db_restore(ctx: DbBackupCtx, project_id: String, backup_id: String) {
    match do_db_restore(&ctx, &project_id, &backup_id).await {
        Ok(()) => info!(project = %project_id, backup = %backup_id, "managed-db restore complete"),
        Err(e) => {
            warn!(project = %project_id, backup = %backup_id, error = %e, "managed-db restore failed")
        }
    }
}

/// Bound the per-project catalog: keep the newest [`DB_BACKUP_KEEP`] COMPLETE backups + any fresh
/// (in-flight) Pending row, and delete everything else — all Failed rows, stale Pending rows
/// (a crashed backup), and Complete rows beyond the retention bound — along with their blobs. Run
/// after every attempt, so a run of failures can't wedge the row cap and disable backups.
async fn prune_db_backups(ctx: &DbBackupCtx, project_id: &str) {
    let backups = match ctx.store.list_db_backups(project_id) {
        Ok(b) => b, // newest-first
        Err(_) => return,
    };
    let now_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0);
    let mut kept_complete = 0usize;
    let mut kept_failed = 0usize;
    for b in backups {
        use jkbase_control::store::BackupStatus;
        let keep = match b.status {
            BackupStatus::Complete => {
                kept_complete += 1;
                kept_complete <= DB_BACKUP_KEEP
            }
            // A fresh Pending is an in-flight backup — never delete it out from under a running
            // pull; a stale one (crashed) is swept.
            BackupStatus::Pending => {
                now_ms.saturating_sub(b.created_at_ms)
                    < jkbase_control::store::Store::BACKUP_STALE_MS
            }
            // Keep the newest few Failed rows so the nightly backoff can see the last failure;
            // drop the rest so they can't wedge the cap.
            BackupStatus::Failed => {
                kept_failed += 1;
                kept_failed <= DB_BACKUP_FAILED_KEEP
            }
        };
        if !keep {
            let _ = ctx.backups.delete(project_id, &b.backup_id).await;
            let _ = ctx.store.delete_db_backup(project_id, &b.backup_id);
        }
    }
}

/// Nightly automatic backups ([RB12]): each tick, back up every managed-DB project whose newest
/// TERMINAL (Complete or Failed) backup is older than [`DB_BACKUP_INTERVAL_MS`] (or has none),
/// skipping any project with a backup already in flight. Concurrency is bounded inside
/// `run_db_backup` by the host-wide `backup_sem` (shared with on-demand). Considering Failed too
/// gives a failing project a full interval of backoff instead of re-firing every 30-min tick.
/// Single-host owns all projects today (mirrors `scheduler_loop`); a future HA layer gates on
/// ownership.
pub(crate) async fn db_backup_nightly_loop(ctx: DbBackupCtx) {
    loop {
        tokio::time::sleep(DB_BACKUP_TICK).await;
        let now_ms = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        let projects = match ctx.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                warn!(error = %e, "nightly db-backup: could not list projects");
                continue;
            }
        };
        for proj in projects {
            let pid = proj.id.clone();
            // A managed DB that has been deployed has a minted admin token.
            if !matches!(ctx.store.get_db_admin_token(&pid), Ok(Some(_))) {
                continue;
            }
            // Skip if a backup is already in flight (single-flight, shared with on-demand).
            if matches!(ctx.store.has_active_backup(&pid), Ok(true)) {
                continue;
            }
            let due = match ctx.store.list_db_backups(&pid) {
                Ok(list) => match list.iter().find(|b| {
                    matches!(
                        b.status,
                        jkbase_control::store::BackupStatus::Complete
                            | jkbase_control::store::BackupStatus::Failed
                    )
                }) {
                    Some(b) => now_ms.saturating_sub(b.created_at_ms) >= DB_BACKUP_INTERVAL_MS,
                    None => true,
                },
                Err(_) => false,
            };
            if !due {
                continue;
            }
            let tenant_id = proj.tenant_id.clone().unwrap_or_default();
            let row = match ctx.store.create_db_backup_auto(&pid, &tenant_id) {
                Ok(r) => r,
                Err(e) => {
                    warn!(project = %pid, error = %e, "nightly db-backup: could not record row");
                    continue;
                }
            };
            // run_db_backup acquires the shared concurrency permit itself; spawn and move on.
            tokio::spawn(run_db_backup(ctx.clone(), pid, row.backup_id.clone()));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::api::DbQueryResult;

    #[test]
    fn rewrite_covers_is_single_flight_per_project() {
        let set = Arc::new(std::sync::Mutex::new(HashSet::new()));
        let a = RewriteInFlight::try_start(&set, "p1").expect("first pass starts");
        assert!(
            RewriteInFlight::try_start(&set, "p1").is_none(),
            "second is refused"
        );
        let b = RewriteInFlight::try_start(&set, "p2").expect("another project is independent");
        drop(a);
        assert!(
            RewriteInFlight::try_start(&set, "p1").is_some(),
            "slot frees on drop"
        );
        drop(b);
        assert!(set.lock().unwrap().is_empty());
    }

    /// The hold is what keeps the idle loop off the VM (`conn_count > 0`), it is keyed so
    /// `cancel_project` reaches it, and it is gone the moment the op ends.
    #[test]
    fn admin_hold_keeps_the_db_vm_warm_and_is_cancellable() {
        let relays = jkbase_proxy::db_relay::DbRelayRegistry::new();
        let (hold, cancel) = hold_db_vm_warm(&relays, "proj").unwrap();
        assert_eq!(relays.conn_count("proj"), 1);
        assert_eq!(
            relays.cancel_key("some-real-akid"),
            0,
            "key revocation never hits it"
        );
        assert_eq!(relays.cancel_project("proj"), 1);
        assert!(cancel.is_cancelled());
        drop(hold);
        assert_eq!(relays.conn_count("proj"), 0);
    }

    #[test]
    fn rewrite_covers_result_passes_the_engine_through_and_explains_a_stale_agent() {
        let engine = br#"{"ok":true,"objects":3,"cover_peers_sound":true}"#.to_vec();
        let r = rewrite_covers_result(DbQueryResult {
            status: 200,
            body: engine.clone(),
        });
        assert_eq!((r.status, r.body), (200, engine));
        let failed = br#"{"ok":false,"error":"write conflict"}"#.to_vec();
        let r = rewrite_covers_result(DbQueryResult {
            status: 200,
            body: failed.clone(),
        });
        assert_eq!(
            (r.status, r.body),
            (200, failed),
            "engine-level failure is the engine's"
        );
        let r = rewrite_covers_result(DbQueryResult {
            status: 404,
            body: b"not found".to_vec(),
        });
        assert_eq!(r.status, 409);
        let v: serde_json::Value = serde_json::from_slice(&r.body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("restart or redeploy"));
    }
}
