//! Per-project data disks (read-write-once): fenced attach under a disk lease, the RAII
//! [`DiskLeaseGuard`] that releases it, and the quota-capped disk sizing.

use crate::ha_lease::DISK_LEASE_TTL;
use crate::project_facts::check_project_has_volumes;
use crate::vm_identity;
use crate::vm_runtime::reap_firecracker;
use anyhow::Result;
use jkbase_substrate::{DataDiskProvider, Ensured, FenceToken, Lease, SubstrateError};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tracing::{info, warn};

/// Data disk size (MiB) created on first use for projects that declare volumes.
pub(crate) const DATA_DISK_MIB: u64 = 1024;

/// Rename any legacy `{id}.ext4` data disks to LocalLoop's `{id}.img` convention so
/// existing per-project data is picked up by the loop-device-backed provider. File
/// contents are untouched; subsequent boots find no `.ext4` and no-op.
pub(crate) async fn migrate_legacy_data_disks(dir: &Path) -> Result<()> {
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // dir absent → nothing to migrate
    };
    while let Some(entry) = rd.next_entry().await? {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ext4") {
            let img = p.with_extension("img");
            if !tokio::fs::try_exists(&img).await.unwrap_or(false) {
                info!(from = %p.display(), to = %img.display(), "migrating legacy data disk to .img");
                tokio::fs::rename(&p, &img).await?;
            } else {
                // Both exist: the loop-managed `.img` is authoritative (storage accounting
                // and the provider already use it), so the legacy `.ext4` is a dead orphan.
                // Reap it BEST-EFFORT — a stuck orphan (immutable attr / read-only FS) must
                // never abort node startup (this runs under `?` in main, before serving);
                // log and leave it for the next boot rather than bricking the whole host.
                warn!(path = %p.display(), "legacy .ext4 data disk shadowed by an existing .img; reaping the orphan");
                if let Err(e) = tokio::fs::remove_file(&p).await {
                    warn!(path = %p.display(), error = %e, "failed to reap shadowed legacy .ext4 orphan; leaving in place");
                }
            }
        }
    }
    Ok(())
}

/// RAII hold on a fenced data disk for a VM's **boot window**. [`fence_data_disk`]
/// returns it ARMED (lease acquired + disk attached). If it is dropped before
/// [`disarm`](DiskLeaseGuard::disarm) — i.e. the boot failed on any `?`
/// (`VmInstance::start`/`restore_from_snapshot`/`wait_for_agent`) — it asynchronously
/// detaches the disk + releases the lease, so a failed boot can NEVER leak the lease
/// (a leak would brick the project with `LeaseHeld`/`RwoUnsafe` until the server
/// restarts). On success the caller `disarm`s it and stores the token in `disk_tokens`
/// for teardown-time release.
pub(crate) struct DiskLeaseGuard {
    data_disk: Arc<dyn DataDiskProvider>,
    lease: Arc<dyn Lease>,
    project_id: String,
    token: FenceToken,
    device: PathBuf,
    /// The fence grew an undersized disk (`[database].size` raised). A snapshot of this VM
    /// still believes the old device size, so the caller must cold-boot, not restore.
    pub(crate) grown: bool,
    armed: bool,
}

impl DiskLeaseGuard {
    pub(crate) fn device(&self) -> PathBuf {
        self.device.clone()
    }
    pub(crate) fn token(&self) -> &FenceToken {
        &self.token
    }
    /// Success path: stop auto-releasing and hand back the token to record in
    /// `disk_tokens` (which the teardown/hibernate paths release).
    pub(crate) fn disarm(mut self) -> FenceToken {
        self.armed = false;
        self.token.clone()
    }

    /// Failure-path release: detach the disk + release the lease **awaited inline**,
    /// then disarm so the [`Drop`] backstop no-ops. Call this on every boot error path
    /// instead of leaning on Drop — Drop can only fire-and-forget (it's sync and can't
    /// block on a tokio runtime), so a re-fence landing before that spawned task ran
    /// would hit a transient, self-clearing `LeaseHeld`/`RwoUnsafe`. Awaiting here closes
    /// that window: the lease + holder are gone before the error returns to the caller.
    pub(crate) async fn release(mut self) {
        if !self.armed {
            return;
        }
        self.armed = false;
        release_data_disk(
            &self.data_disk,
            &self.lease,
            &self.project_id,
            self.token.clone(),
        )
        .await;
    }
}

impl Drop for DiskLeaseGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // BACKSTOP ONLY. Normal boot-error paths call `release().await` (which awaits the
        // cleanup before returning); reaching Drop still armed means an unexpected drop —
        // a panic unwind or a future cancellation. Release fire-and-forget here: Drop is
        // sync and can't block on the runtime, and guard against being dropped outside a
        // runtime (e.g. during shutdown) so we never panic in Drop — the flock releases on
        // process exit anyway.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        warn!(project = %self.project_id, "data-disk boot guard dropped while armed (panic/cancel) — detaching + releasing lease");
        let (dd, ls, id, tok) = (
            self.data_disk.clone(),
            self.lease.clone(),
            self.project_id.clone(),
            self.token.clone(),
        );
        handle.spawn(async move {
            let _ = dd.detach(&id).await;
            let _ = ls.release(&tok).await;
        });
    }
}

/// Acquire the data-disk lease + attach the disk **read-write-once**, fencing any
/// prior writer, and return an armed [`DiskLeaseGuard`]. The armed guard is built the
/// instant `acquire` succeeds and OWNS the `ensure`/`attach` steps, so if those error
/// — OR the whole future is cancelled mid-attach (the wake/deploy callback is awaited
/// inline by the proxy, so a client disconnect cancels it) — the guard drops and
/// releases the lease. On `RwoUnsafe` (a prior writer still proven alive) it reaps a
/// stale Firecracker and retries once. After success the caller `disarm`s the guard.
pub(crate) async fn fence_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    project_id: &str,
    disk_mib: u64,
) -> Result<DiskLeaseGuard> {
    let token = lease
        .acquire(project_id, host_id, DISK_LEASE_TTL)
        .await
        .map_err(|e| anyhow::anyhow!("lease acquire for {project_id}: {e}"))?;
    // Armed BEFORE the slow ensure/attach: any error or cancellation from here drops
    // the guard (which detaches + releases the lease) — no acquire→attach leak.
    let mut guard = DiskLeaseGuard {
        data_disk: data_disk.clone(),
        lease: lease.clone(),
        project_id: project_id.to_string(),
        token,
        device: PathBuf::new(),
        grown: false,
        armed: true,
    };
    let (device, ensured) = fence_attach(data_disk, project_id, guard.token(), disk_mib).await?;
    guard.device = device;
    guard.grown = ensured == Ensured::Grown;
    if guard.grown {
        info!(project = %project_id, disk_mib, "grew data disk; the guest grows its fs at mount");
    }
    Ok(guard)
}

pub(crate) async fn fence_attach(
    data_disk: &Arc<dyn DataDiskProvider>,
    project_id: &str,
    token: &FenceToken,
    disk_mib: u64,
) -> Result<(PathBuf, Ensured)> {
    // `ensure` is grow-or-create and NEVER shrinks, so a re-sized `[database].size`
    // grows the disk on the next boot and a smaller value is a safe no-op (no data loss).
    // Runs before `attach_rwo`'s live-writer check, but a grow under a still-live prior writer
    // is harmless: its loop binding keeps the old capacity, and attach binds a fresh one.
    let ensured = data_disk
        .ensure(project_id, disk_mib * 1024 * 1024)
        .await
        .map_err(|e| anyhow::anyhow!("ensure data disk {project_id}: {e}"))?;
    let device = match data_disk.attach_rwo(project_id, token).await {
        Ok(d) => d,
        Err(SubstrateError::RwoUnsafe { .. }) => {
            warn!(project = %project_id, "data disk held by a live prior writer; reaping stale Firecracker and retrying attach");
            reap_firecracker(project_id).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            data_disk
                .attach_rwo(project_id, token)
                .await
                .map_err(|e| anyhow::anyhow!("attach_rwo after reap {project_id}: {e}"))?
        }
        Err(e) => return Err(anyhow::anyhow!("attach_rwo {project_id}: {e}")),
    };
    Ok((device.path, ensured))
}

/// Release a project's data disk: detach the device + release the lease so another
/// host/boot can acquire without waiting out the TTL. Best-effort (teardown path).
pub(crate) async fn release_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    project_id: &str,
    token: FenceToken,
) {
    let _ = data_disk.detach(project_id).await;
    let _ = lease.release(&token).await;
}

/// Desired size (MiB) of data disk `disk_id` (a rendered vm id: `{id}` for the app VM, `{id}.db`
/// for a dedicated DB VM): the managed-DB `[database].size` (parsed host-side at deploy into the
/// BASE project's `_database.json` `size_mib`) when present, else the platform default
/// [`DATA_DISK_MIB`]. Read at deploy AND every wake so a re-sized DB grows on the next boot
/// (`ensure` never shrinks). Floored at the default — a disk is never smaller than the platform
/// minimum, so a too-small `size` is harmless. A non-DB project gets the default unchanged.
///
/// Capped PROJECT-WIDE at the storage quota (`cap_bytes`): `size` is tenant input and a disk is
/// real host capacity the guest can fill between checks, while the quota is otherwise only checked
/// at deploy / object-write time. The DB-holding disk gets the quota MINUS everything else the
/// project reserves ([`jkbase_common::storage::project_reserved_bytes`]: its other disks at their
/// full size — what their guests can fill, not what they've filled — plus content, the live
/// deployment, build caches and the object store), so the next quota check still fits and a
/// dedicated project can't spend its budget once per disk. An app disk a dedicated project will
/// create for its volumes but hasn't yet is reserved at its fixed default, so boot order can't
/// decide the total. A larger `size` is clamped, not refused, so the project still boots.
/// Residuals: the per-disk floor wins over the budget, and a dedicated project that adds volumes
/// AFTER its DB disk took the budget gets a default app disk on top (each ≤ one [`DATA_DISK_MIB`]);
/// a disk grown before its quota was lowered keeps its size (`ensure` never shrinks). The deploy
/// cap then refuses any deploy that grows such a project further.
///
/// The budget walk (object store included) runs only when the disk would actually GROW — never
/// on the steady-state wake, whose latency it would otherwise tax. Blocking fs: callers go through
/// [`data_disk_mib`].
///
/// `holds_db`: whether this disk holds the managed DB (the DB VM's, or a co-located app VM's).
/// A dedicated project's app-VM disk only carries its own volumes, so it stays at the default.
pub(crate) fn data_disk_mib_for(
    data_dir: &Path,
    disk_id: &str,
    holds_db: bool,
    cap_bytes: u64,
) -> u64 {
    if !holds_db {
        return DATA_DISK_MIB;
    }
    const MIB: u64 = 1024 * 1024;
    let (base, role) = vm_identity::split_vm_id(disk_id);
    let path = data_dir
        .join("hosting")
        .join(base)
        .join("live")
        .join("_database.json");
    let configured = std::fs::read_to_string(&path)
        .ok()
        .and_then(|c| serde_json::from_str::<serde_json::Value>(&c).ok())
        .and_then(|v| v.get("size_mib").and_then(serde_json::Value::as_u64));
    let wanted = configured.unwrap_or(0).max(DATA_DISK_MIB);
    // This disk's slot among `data_disk_images` (the app slot — `{base}.img` or legacy `.ext4` —
    // or `{base}.db.img`), and its current logical size.
    let db_img = data_dir.join("data-disks").join(format!("{base}.db.img"));
    let is_db_disk = role == vm_identity::VmRole::Db;
    let disks = jkbase_common::storage::data_disk_images(data_dir, base);
    let own_bytes = disks
        .iter()
        .filter(|p| (**p == db_img) == is_db_disk)
        .filter_map(|p| std::fs::metadata(p).ok())
        .fold(0u64, |acc, md| acc.saturating_add(md.len()));
    if wanted.saturating_mul(MIB) <= own_bytes {
        return wanted; // no growth: `ensure` is a no-op, skip the budget walk
    }
    let mut other_bytes =
        jkbase_common::storage::project_reserved_bytes(data_dir, base).saturating_sub(own_bytes);
    let app_disk_exists = disks.iter().any(|p| *p != db_img);
    if is_db_disk && !app_disk_exists && check_project_has_volumes(data_dir, base) {
        other_bytes = other_bytes.saturating_add(DATA_DISK_MIB * MIB);
    }
    let budget_mib = cap_bytes.saturating_sub(other_bytes) / MIB;
    wanted.min(budget_mib).max(DATA_DISK_MIB)
}

/// [`data_disk_mib_for`] off the async runtime (its budget walk can cover a large object store).
/// A failed task falls back to the platform floor — safe, as `ensure` never shrinks a disk.
pub(crate) async fn data_disk_mib(
    data_dir: &Path,
    disk_id: &str,
    holds_db: bool,
    cap_bytes: u64,
) -> u64 {
    let (dd, id) = (data_dir.to_path_buf(), disk_id.to_string());
    tokio::task::spawn_blocking(move || data_disk_mib_for(&dd, &id, holds_db, cap_bytes))
        .await
        .unwrap_or(DATA_DISK_MIB)
}

/// The project's storage quota in bytes, the ceiling for its data disk
/// ([`data_disk_mib_for`]). A store error falls back to the platform default quota.
pub(crate) fn disk_cap_bytes(store: &jkbase_control::store::Store, project_id: &str) -> u64 {
    store
        .get_quota(project_id)
        .map(|q| q.storage_bytes_max)
        .unwrap_or(jkbase_control::store::DEFAULT_QUOTA.storage_bytes_max)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The fail-open routing at the heart of "redeploys never brick": every reason a snapshot
    /// can't be trusted must route to a cold boot (None), and only a fully-coherent snapshot
    /// (stamped+present rootfs blob + matching deployment version) restores.
    /// The live tree's own manifests (`_database.json`, …) count against the project budget, so
    /// a budget that would land exactly on a GiB boundary rounds down one MiB.
    const LIVE_MIB: u64 = 1;

    #[test]
    fn data_disk_size_is_floored_at_default_and_capped_at_quota() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-disksize-{nanos}"));
        let live = root.join("hosting").join("p").join("live");
        std::fs::create_dir_all(&live).unwrap();
        let gib = 1024 * 1024 * 1024u64;
        let set = |mib: u64| {
            std::fs::write(
                live.join("_database.json"),
                format!(r#"{{"size_mib": {mib}}}"#),
            )
            .unwrap()
        };
        // No `_database.json` → the default.
        assert_eq!(data_disk_mib_for(&root, "p", true, 16 * gib), DATA_DISK_MIB);
        set(8192);
        assert_eq!(data_disk_mib_for(&root, "p", true, 16 * gib), 8192);
        // Too small → floored at the default.
        set(10);
        assert_eq!(data_disk_mib_for(&root, "p", true, 16 * gib), DATA_DISK_MIB);
        // Tenant-declared size beyond the storage quota → clamped to the quota.
        set(1024 * 1024 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p", true, 16 * gib),
            16 * 1024 - LIVE_MIB
        );
        // A quota below the default never shrinks a disk below the platform floor.
        assert_eq!(data_disk_mib_for(&root, "p", true, 1), DATA_DISK_MIB);
        // A dedicated project's app-VM disk doesn't hold the DB → default, whatever `size` says.
        set(8192);
        assert_eq!(
            data_disk_mib_for(&root, "p", false, 16 * gib),
            DATA_DISK_MIB
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// The quota caps a project's disks TOGETHER, not each: a dedicated project's DB disk gets
    /// only what its other disks (by logical size — what their guests can fill) leave over.
    #[test]
    fn data_disk_size_is_capped_project_wide_across_app_and_db_disks() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-diskbudget-{nanos}"));
        let live = root.join("hosting").join("p").join("live");
        let disks = root.join("data-disks");
        std::fs::create_dir_all(&live).unwrap();
        std::fs::create_dir_all(&disks).unwrap();
        let (mib, gib) = (1024 * 1024u64, 1024 * 1024 * 1024u64);
        // Sparse images: logical size only, nothing allocated.
        let disk = |name: &str, mib_len: u64| {
            std::fs::File::create(disks.join(name))
                .unwrap()
                .set_len(mib_len * mib)
                .unwrap();
        };
        std::fs::write(live.join("_database.json"), r#"{"size_mib": 1048576}"#).unwrap();

        // No other disk yet → the DB disk may take the whole quota.
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            16 * 1024 - LIVE_MIB
        );
        // A dedicated project that declares volumes will get a default app disk: reserved up
        // front, so the DB VM booting first can't spend it.
        std::fs::create_dir_all(live.join("_servers")).unwrap();
        std::fs::write(
            live.join("_servers").join("api.json"),
            r#"{"volumes": [{"name": "data", "mount": "/data"}]}"#,
        )
        .unwrap();
        assert!(check_project_has_volumes(&root, "p"));
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            16 * 1024 - DATA_DISK_MIB - LIVE_MIB
        );
        std::fs::remove_dir_all(live.join("_servers")).unwrap();

        // An existing app disk (here grown to 3 GiB, e.g. a former co-located DB) is subtracted
        // at its LOGICAL size, though sparse — its guest can still fill it.
        disk("p.img", 3 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            13 * 1024 - LIVE_MIB
        );
        // The legacy `.ext4` app slot counts the same way when there's no `.img`.
        std::fs::remove_file(disks.join("p.img")).unwrap();
        disk("p.ext4", 3 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            13 * 1024 - LIVE_MIB
        );
        // The DB disk's OWN current size never counts against itself (re-sizing on wake).
        disk("p.db.img", 13 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            13 * 1024 - LIVE_MIB
        );
        // …and it counts against a co-located app disk (a stale sibling after a tier change).
        assert_eq!(
            data_disk_mib_for(&root, "p", true, 16 * gib),
            3 * 1024 - LIVE_MIB
        );
        // Other projects' disks are never part of this budget.
        disk("q.db.img", 8 * 1024);
        disk("p2.img", 8 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            13 * 1024 - LIVE_MIB
        );
        // A budget exhausted by other disks still floors at the platform minimum.
        disk("p.ext4", 16 * 1024);
        assert_eq!(
            data_disk_mib_for(&root, "p.db", true, 16 * gib),
            DATA_DISK_MIB
        );
        // A dedicated project's app disk doesn't hold the DB → the default, budget irrelevant.
        assert_eq!(
            data_disk_mib_for(&root, "p", false, 16 * gib),
            DATA_DISK_MIB
        );
        let _ = std::fs::remove_dir_all(&root);
    }

    /// Everything ELSE the project reserves comes out of the disk budget too (so the next deploy /
    /// object write still fits), but only when the disk would grow — a disk already at its wanted
    /// size is left alone however full the rest of the quota is.
    #[test]
    fn data_disk_budget_subtracts_non_disk_usage_only_when_growing() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let root = std::env::temp_dir().join(format!("jkbase-diskbudget2-{nanos}"));
        let live = root.join("hosting").join("p").join("live");
        std::fs::create_dir_all(&live).unwrap();
        let (mib, gib) = (1024 * 1024u64, 1024 * 1024 * 1024u64);
        std::fs::write(live.join("_database.json"), r#"{"size_mib": 4096}"#).unwrap();
        // 3 GiB of objects (sparse, so the test stays cheap; `dir_bytes` counts logical length).
        let bkt = root.join("objectstore").join("p").join("b");
        std::fs::create_dir_all(&bkt).unwrap();
        std::fs::File::create(bkt.join("o"))
            .unwrap()
            .set_len(3 * gib)
            .unwrap();
        // Creating the DB disk under a 5 GiB quota: 5 − 3 (objects) − the manifest → just under 2 GiB,
        // not the 4 GiB `size`.
        let got = data_disk_mib_for(&root, "p.db", true, 5 * gib);
        assert!((DATA_DISK_MIB..2048).contains(&got), "got {got}");
        // Already at its wanted size → returned as-is, no budget applied (no shrink, no walk).
        let disks = root.join("data-disks");
        std::fs::create_dir_all(&disks).unwrap();
        std::fs::File::create(disks.join("p.db.img"))
            .unwrap()
            .set_len(4096 * mib)
            .unwrap();
        assert_eq!(data_disk_mib_for(&root, "p.db", true, 5 * gib), 4096);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[tokio::test]
    async fn disk_lease_renewal_signals_loss_after_release() {
        // The self-fence trigger (HA P2): while we hold the disk lease, renew succeeds;
        // once it is lost (here: released ≈ superseded by a survivor / expired under a
        // partition), renew fails — that Err is what drives self_fence_project.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let leases = std::env::temp_dir().join(format!("jkbase-diskfence-{nanos}"));
        let l = jkbase_substrate::FlockLease::open(leases.clone(), "host-a").unwrap();
        let t = l.acquire("proj-x", "host-a", DISK_LEASE_TTL).await.unwrap();
        assert!(
            l.renew(&t, DISK_LEASE_TTL).await.is_ok(),
            "held → renew succeeds (no fence)"
        );
        l.release(&t).await.unwrap();
        assert!(
            l.renew(&t, DISK_LEASE_TTL).await.is_err(),
            "lost → renew fails → self-fence fires"
        );
        let _ = std::fs::remove_dir_all(&leases);
    }
}
