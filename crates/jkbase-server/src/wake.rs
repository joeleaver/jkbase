//! Waking a project on demand: the single-flight wake entry points, the guard that resets a failed
//! `Waking`, the proxy's two wake seams (app VM / DB reach plane), and the restore-vs-cold-boot
//! decision.

use crate::boot_reconcile::project_can_wake;
use crate::log_shipper::LogShipper;
use crate::platform::{PlatformState, VmLifecycle};
use crate::project_facts::db_reach_target_vm;
use crate::wake_vm::wake_project_inner;
use crate::{rootfs_cas, vm_identity};
use anyhow::Result;
use jkbase_control::store::{ProjectState, SnapshotMeta};
use jkbase_proxy::DomainMap;
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;

/// RAII reset of the in-memory `Waking` lifecycle for the task that elected itself the wake
/// driver. On drop WITHOUT an explicit `commit()`, it removes the project's `Waking` entry so
/// the project can be re-driven on the next request. This closes the brick (incident: nlnwt)
/// where a client disconnect — the proxy awaits the wake inline per-request, so a disconnect
/// DROPS this future mid-boot — or ANY early `?` exit (alloc read, `setup_tap`, `fence_data_disk`,
/// the boot block) left `vm_states` stuck at `Waking` forever, recoverable only by a full service
/// restart. Drop can't await the async mutex, so it spawns the removal (eventually-consistent),
/// but it ALWAYS fires: the success path `commit()`s (disarming it); every other exit, including
/// cancel/unwind, runs Drop. It only removes an entry that is STILL `Waking`, so it can't stomp a
/// concurrent transition.
pub(crate) struct WakingGuard {
    platform: Arc<Mutex<PlatformState>>,
    project_id: String,
    committed: bool,
}

impl WakingGuard {
    pub(crate) fn new(platform: Arc<Mutex<PlatformState>>, project_id: String) -> Self {
        Self {
            platform,
            project_id,
            committed: false,
        }
    }
    /// The wake reached `Running`; disarm the reset.
    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for WakingGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        let platform = self.platform.clone();
        let pid = self.project_id.clone();
        tokio::spawn(async move {
            let mut plat = platform.lock().await;
            if plat.vm_states.get(&pid) == Some(&VmLifecycle::Waking) {
                plat.vm_states.remove(&pid);
                plat.vm_rootfs_hashes.remove(&pid);
            }
        });
    }
}

/// How long after a failed wake to fast-fail subsequent wakes of the same project, so a broken
/// app (or hostile traffic at a doomed project) can't spin unbounded full boot attempts — each
/// of which bumps the data-disk lease epoch and spawns Firecracker(s). Short enough to keep the
/// self-healing "next request re-drives a boot" property.
pub(crate) const WAKE_BACKOFF: Duration = Duration::from_secs(5);

/// Wake a project, refusing if it is over an enforced quota. The quota gate
/// reads QUOTA_STATUS (the metering loop's source of truth) so a request racing
/// the over-quota hibernation is still refused. All other failures are transient
/// (`Unavailable`) and the proxy retries them.
pub(crate) async fn wake_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> std::result::Result<String, jkbase_proxy::WakeError> {
    // Quota + deployability gate on the BASE project: waking a DB VM (`{id}.db`, driven by the DB
    // reach seams) is gated on its owning project's quota + content (the DB VM has no project row
    // of its own), while `wake_project_inner` boots the rendered id. For an app VM base == id.
    let base = vm_identity::base_project_id(project_id);
    {
        let plat = platform.lock().await;
        if let Ok(Some(status)) = plat.store.get_quota_status(base)
            && status.bandwidth_blocked
        {
            return Err(jkbase_proxy::WakeError::OverQuota(
                status
                    .blocked_reason
                    .unwrap_or_else(|| "over quota".to_string()),
            ));
        }
        // Authoritative gate: a registered project with no deployable artifacts can
        // never wake (cold-boot content + snapshot both gone). Persist NeedsRedeploy
        // and surface a clear "redeploy" rather than looping the proxy on the
        // transient "starting up" path. The boot reconcile marks these too; this also
        // catches a project whose artifacts go missing while the server is up.
        if !project_can_wake(&plat.data_dir, &plat.store, base) {
            if let Ok(Some(mut proj)) = plat.store.get_project(base)
                && proj.state != ProjectState::NeedsRedeploy
            {
                proj.state = ProjectState::NeedsRedeploy;
                let _ = plat.store.update_project(&proj);
                let _ = plat.store.remove_snapshot_meta(base);
            }
            return Err(jkbase_proxy::WakeError::Gone(
                "no deployable content — redeploy to bring it back".to_string(),
            ));
        }
        // Surface the WAKE_BACKOFF throttle as `RateLimited` (distinct from a transient
        // `Unavailable`) so a rate-cap read is legible in metrics and the L4 wake plane can
        // tell "throttled" from "boot failed" — the design's promote-the-bail delta (§3(c)).
        // `wake_project_inner` keeps its own backoff check as a TOCTOU backstop.
        if let Some(t) = plat.wake_failures.get(project_id)
            && t.elapsed() < WAKE_BACKOFF
        {
            return Err(jkbase_proxy::WakeError::RateLimited(format!(
                "project {project_id} recently failed to wake; retry shortly"
            )));
        }
    }
    wake_project_inner(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| jkbase_proxy::WakeError::Unavailable(e.to_string()))
}

/// The wake seam for anything that then talks to the project's APP VM — HTTP/WebSocket routing
/// and L4 UDP ingress. Wakes the base project id as-is, so a `tier="dedicated"` project's app VM
/// comes up (never its sibling DB VM — the caller forwards tenant traffic to the returned IP).
pub(crate) fn app_wake_callback(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> jkbase_proxy::WakeCallback {
    Arc::new(move |project_id: String| {
        let (platform, routing, domains, shipper) = (
            platform.clone(),
            routing.clone(),
            domain_map.clone(),
            shipper.clone(),
        );
        Box::pin(
            async move { wake_project(&project_id, platform, routing, domains, shipper).await },
        )
    })
}

/// The wake seam for the managed-DB reach plane (`jkbase-db` edge, app→DB host gateway): follows
/// [`wake_db_reach`] to the VM serving the DB. Never hand this to an app-traffic edge — for a
/// dedicated project it resolves the DB VM, and app traffic would then be forwarded there.
pub(crate) fn db_reach_wake_callback(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> jkbase_proxy::WakeCallback {
    Arc::new(move |project_id: String| {
        let (platform, routing, domains, shipper) = (
            platform.clone(),
            routing.clone(),
            domain_map.clone(),
            shipper.clone(),
        );
        Box::pin(
            async move { wake_db_reach(&project_id, platform, routing, domains, shipper).await },
        )
    })
}

/// Wake the VM that serves a project's managed DB for the reach plane, and return its IP. Resolves
/// the target via [`db_reach_target_vm`] — the sibling DB VM (`{id}.db`) when `tier="dedicated"`,
/// else the app VM — then delegates to [`wake_project`] (whose gates run on the base project). All
/// four DB reach seams (external `:443` edge, console query/schema/status, backup, restore) route
/// through this so a dedicated project is uniformly followed to its DB VM; the splice secret + dial
/// on `:80` are unchanged (the DB VM's agent holds the same secret).
pub(crate) async fn wake_db_reach(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> std::result::Result<String, jkbase_proxy::WakeError> {
    let target = {
        let plat = platform.lock().await;
        let target = db_reach_target_vm(&plat.data_dir, project_id);
        // A dedicated DB with no lifecycle state, allocation or disk isn't provisioned: dropped
        // (`jkbase db drop`), or a first deploy hasn't reached `boot_db_vm` yet. Only a deploy
        // provisions it, so don't let every connect re-drive a doomed no-allocation cold boot
        // (`handle_deploy` of the `.db` id) under the platform lock. Transient-shaped (503 +
        // retry), as the first-deploy case resolves on its own.
        if target != project_id
            && !plat.vm_states.contains_key(&target)
            && matches!(plat.store.get_vm_allocation(&target), Ok(None))
            && !plat.data_disk.exists(&target).await.unwrap_or(true)
        {
            return Err(jkbase_proxy::WakeError::Unavailable(format!(
                "the dedicated database of {project_id} isn't provisioned (dropped, or its deploy \
                 is still booting it) — redeploy if it doesn't come up"
            )));
        }
        target
    };
    wake_project(&target, platform, routing, domain_map, shipper).await
}

/// Decide whether a hibernation snapshot can be restored **byte-correct**, or whether the wake
/// must fail OPEN to a clean cold boot from the current rootfs. Returns `(Some(hash)` to restore
/// against that immutable CAS blob | `None` to cold-boot, a `wake_outcome` label`)`.
///
/// A restore is viable iff the snapshot stamps the rootfs it actually ran (present + valid-hex,
/// its CAS blob still on disk) AND its deployment version still matches the project's current
/// version — which transitively guarantees the metadata image + erofs layers it bakes by fixed
/// path are the current, coherent set. Every other case (no snapshot, missing files, a legacy
/// unstamped record, a reaped/renamed rootfs blob, or version drift) cold-boots — never a brick.
pub(crate) fn snapshot_restore_decision(
    snap_meta: Option<&SnapshotMeta>,
    current_version: Option<u64>,
    cas_dir: &Path,
) -> (Option<String>, &'static str) {
    let Some(m) = snap_meta else {
        return (None, "coldboot_fresh");
    };
    if !(Path::new(&m.snapshot_path).exists() && Path::new(&m.mem_file_path).exists()) {
        return (None, "skipped_snapshot_files_missing");
    }
    match m.base_rootfs_hash.as_deref() {
        None => (None, "skipped_legacy_unstamped"),
        Some(h) if !rootfs_cas::is_sha256_hex(h) => (None, "skipped_bad_hash"),
        Some(h) if !rootfs_cas::blob_path(cas_dir, h).is_file() => {
            (None, "skipped_rootfs_blob_missing")
        }
        Some(_) if m.deployment_version != current_version => (None, "skipped_version_drift"),
        Some(h) => (Some(h.to_string()), "restored"),
    }
}

/// A non-driver request waits here for the elected wake driver to publish the project's route.
/// It also fast-fails the moment the driver leaves `Waking`/`Running` WITHOUT a route — i.e. the
/// driver failed and reset the state — instead of hanging the full 30s, so the proxy returns
/// Retry-After promptly and a fresh request re-drives a boot. (`Running` is tolerated: there's a
/// brief window where the driver set `Running` but hasn't registered the route yet.)
pub(crate) async fn wait_for_route(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
) -> Result<String> {
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        {
            let table = routing.read().await;
            if let Some(ip) = table.get(project_id) {
                return Ok(ip.clone());
            }
        }
        let p = platform.lock().await;
        match p.vm_states.get(project_id) {
            Some(VmLifecycle::Waking) | Some(VmLifecycle::Running) => {}
            _ => {
                drop(p);
                anyhow::bail!("wake of {project_id} did not complete; retry");
            }
        }
    }
    anyhow::bail!("timed out waiting for {project_id} to wake");
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::store::SnapshotMeta;

    /// The fail-open routing at the heart of "redeploys never brick": every reason a snapshot
    /// can't be trusted must route to a cold boot (None), and only a fully-coherent snapshot
    /// (stamped+present rootfs blob + matching deployment version) restores.
    #[test]
    fn snapshot_restore_decision_fails_open_on_every_mismatch() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-decision-{nanos}"));
        let cas = root.join("base-rootfs");
        std::fs::create_dir_all(&cas).unwrap();
        let snap = root.join("snapshot");
        let mem = root.join("mem");
        std::fs::write(&snap, b"s").unwrap();
        std::fs::write(&mem, b"m").unwrap();
        let good_hash = "a".repeat(64);
        std::fs::write(rootfs_cas::blob_path(&cas, &good_hash), b"rootfs").unwrap();

        let base = |hash: Option<String>, ver: Option<u64>| SnapshotMeta {
            project_id: "p".into(),
            snapshot_path: snap.to_string_lossy().into_owned(),
            mem_file_path: mem.to_string_lossy().into_owned(),
            created_at: 0,
            vcpu_count: 1,
            mem_size_mib: 1024,
            base_rootfs_hash: hash,
            deployment_version: ver,
        };

        // No snapshot at all → fresh cold boot.
        assert_eq!(
            snapshot_restore_decision(None, Some(3), &cas),
            (None, "coldboot_fresh")
        );
        // Fully coherent → restore against the stamped blob.
        let m = base(Some(good_hash.clone()), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas),
            (Some(good_hash.clone()), "restored")
        );
        // Legacy unstamped → cold boot.
        let m = base(None, Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_legacy_unstamped"
        );
        // Stamped hash whose blob was reaped/never-placed → cold boot (this is the exact
        // self-healing path that saves a project from a GC over-deletion).
        let m = base(Some("b".repeat(64)), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_rootfs_blob_missing"
        );
        // Non-hex stamp → cold boot (never trust it as a path component).
        let m = base(Some("../etc".to_string()), Some(3));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_bad_hash"
        );
        // Version drift (project redeployed since hibernate) → cold boot, so a stale metadata
        // image / secrets / layers can't be restored under the wrong version.
        let m = base(Some(good_hash.clone()), Some(2));
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_version_drift"
        );
        // Snapshot files reaped out from under the record → cold boot.
        let m = base(Some(good_hash.clone()), Some(3));
        std::fs::remove_file(&snap).unwrap();
        assert_eq!(
            snapshot_restore_decision(Some(&m), Some(3), &cas).1,
            "skipped_snapshot_files_missing"
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
