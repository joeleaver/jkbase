//! The dedicated managed-DB VM (`{project_id}.db`, P2): booting or replacing it on deploy, the
//! guard that serialises its boots, and waiting for it to come up.

use crate::agent_client::wait_for_agent;
use crate::data_disk::{data_disk_mib, disk_cap_bytes, fence_data_disk, release_data_disk};
use crate::platform::{PlatformState, RUNTIME_CGROUP_PARENT, VmLifecycle, lifecycle_in_flight};
use crate::tap::setup_tap;
use crate::vm_runtime::write_handoff_record;
use crate::{handoff, layer_plan, vm_identity};
use anyhow::{Context, Result};
use jkbase_control::store::VmAllocation;
use jkbase_orch::vm::{VmConfig, VmInstance};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;

/// Boot (or, on redeploy, replace) a project's dedicated DB VM (`{project_id}.db`). Mirrors the
/// app-VM cold boot but for a lean, rhypedb-only sibling: its OWN IP/TAP + data disk
/// (`{id}.db.img`) + metadata image (`content-images/{id}.db.ext4`, built `DbOnly`), booted at
/// [`vm_identity::DB_VM_SIZE`] and committed into the platform maps under the rendered id. All
/// deployment/store reads use the BASE `project_id` (the DB VM has no `hosting/<id>.db/` — it
/// reuses the app's live tree); all per-VM-instance state uses the rendered `db_id`. A boot error
/// propagates so the caller fails the deploy (retryable) rather than half-provisioning.
pub(crate) async fn boot_db_vm(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    db_reach: Option<&jkbase_common::config::DbReachFacts>,
) -> Result<()> {
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);

    // Count this boot in flight for its whole life (allocation read → fence → commit), so a
    // tenant's `drop_dedicated_db` can't free the allocation/TAP/disk out from under it. The guard
    // is armed with no await between it and the increment, so a cancellation can never make it
    // decrement a count it didn't add.
    *platform
        .lock()
        .await
        .db_boots
        .entry(db_id.clone())
        .or_default() += 1;
    let _boot_guard = DbBootGuard::new(platform.clone(), db_id.clone());

    // Snapshot the substrate handles + supersede any prior DB VM (redeploy), then release the lock
    // for the slow build + fence + boot.
    let (
        disk_cap,
        data_dir,
        dd,
        ls,
        hid,
        firecracker_bin,
        kernel_path,
        rootfs_path,
        platform_egress,
        alloc,
    ) = {
        // Wait out an in-flight wake/hibernate OF THE DB VM before superseding it (the caller's
        // `handle_deploy` gate only covers the APP id). Hibernate drops the lock mid-snapshot
        // still holding the disk token while its paused FC maps the disk: releasing that token
        // under it lets our fence hit `RwoUnsafe` → `reap_firecracker` the paused FC, after which
        // hibernate's second section would tear down OUR commit (the incarnation check in
        // `hibernate_project` is the backstop for that; this wait keeps us from causing it). Same
        // ~80s budget as `handle_deploy` (outlasts hibernate's 3s ship + 60s snapshot); on expiry
        // FAIL the boot — the deploy is retryable. We only READ `vm_states` here: this boot never
        // writes a shared `Waking` it doesn't own (that broke the dedicated-DB drop's safety). The
        // wait and the supersede share ONE lock section, so nothing starts between THEM; after it,
        // while we build + fence + boot unlocked, a DB wake may still start (the id is left
        // `Hibernated`/`Running`) — the disk lease is what excludes it (one side fails LeaseHeld,
        // retryably), and a hibernate can't (we removed the VM handle it needs).
        let mut attempt = 0;
        let mut plat = loop {
            let plat = platform.lock().await;
            if !lifecycle_in_flight(plat.vm_states.get(&db_id)) {
                break plat;
            }
            drop(plat);
            if attempt >= 400 {
                anyhow::bail!(
                    "DB VM {db_id} busy (wake/hibernate still in flight after ~80s); retry deploy"
                );
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
        };

        // Supersede a prior DB VM incarnation (redeploy): drop its stale snapshot, stop it, and
        // release its data-disk hold before re-fencing — mirrors the app redeploy path.
        let snapshot_dir = plat.data_dir.join("snapshots").join(&db_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(&db_id);
        if let Some(mut old) = plat.vms.remove(&db_id) {
            let _ = old.stop().await;
        }
        plat.vm_incarnations.retire(&db_id);
        plat.vm_rootfs_hashes.remove(&db_id);
        handoff::remove(&plat.data_dir.join("run"), &db_id);
        if let Some(token) = plat.disk_tokens.remove(&db_id) {
            let dd = plat.data_disk.clone();
            let ls = plat.lease.clone();
            release_data_disk(&dd, &ls, &db_id, token).await;
        }

        // Allocate (or reuse) the DB VM's own IP under the `{id}.db` allocation row — a 2nd octet.
        let alloc = match plat.store.get_vm_allocation(&db_id)? {
            Some(existing) => existing,
            None => {
                let (ip, tap, mac) = plat.allocate_ip()?;
                let a = VmAllocation {
                    project_id: db_id.clone(),
                    ip,
                    tap_device: tap,
                    mac,
                    host_id: plat.host_id.clone(),
                    placement_epoch: 1,
                };
                plat.store.save_vm_allocation(&a)?;
                info!(project = %project_id, db_vm = %db_id, ip = %a.ip, "allocated DB VM IP");
                a
            }
        };
        let disk_cap = disk_cap_bytes(&plat.store, project_id);
        (
            disk_cap,
            plat.data_dir.clone(),
            plat.data_disk.clone(),
            plat.lease.clone(),
            plat.host_id.clone(),
            plat.firecracker_bin.clone(),
            plat.kernel_path.clone(),
            plat.base_rootfs_path.clone(),
            plat.platform_egress.clone(),
            alloc,
        )
    };

    let content_dir = data_dir.join("hosting").join(project_id).join("live");
    let runtime_dir = data_dir.join("run");
    setup_tap(&alloc.tap_device).await?;

    // Build the DB VM's OWN metadata image (DbOnly: rhypedb overlay + `_database.json`/`_database/`
    // only — no app servers/routes/sites) + resolve its layer blobs from the same live tree.
    let metadata_image_path = data_dir
        .join("content-images")
        .join(format!("{db_id}.ext4"));
    let plan = {
        let content_dir = content_dir.clone();
        let store_dir = data_dir.join("baselayers");
        let out = metadata_image_path.clone();
        let db_reach = db_reach.cloned();
        tokio::task::spawn_blocking(move || -> anyhow::Result<layer_plan::LayerPlan> {
            let plan = layer_plan::compute_layer_plan_with(
                &content_dir,
                &store_dir,
                true,
                true,
                layer_plan::ImageContent::DbOnly,
            )?;
            layer_plan::build_metadata_image_with(
                &content_dir,
                &plan,
                &std::collections::BTreeMap::new(),
                &platform_egress,
                None,
                db_reach.as_ref(),
                None, // the DB VM carries no L4 ports (L4 is app-VM only)
                &out,
                layer_plan::ImageContent::DbOnly,
            )?;
            Ok(plan)
        })
        .await
        .context("DB VM metadata image build task")??
    };

    // Fence the DB VM's OWN data disk (`{id}.db.img`), sized from the BASE project's
    // `_database.json` (`[database].size`) within the project-wide storage budget. The `.db`
    // scope is validator-legal (F1).
    let disk_mib = data_disk_mib(&data_dir, &db_id, true, disk_cap).await;
    let disk_guard = fence_data_disk(&dd, &ls, &hid, &db_id, disk_mib).await?;

    let db_size = vm_identity::vm_size_for(vm_identity::VmRole::Db);
    let config = VmConfig {
        firecracker_bin,
        kernel_path,
        rootfs_path,
        metadata_image_path: Some(metadata_image_path),
        layer_paths: plan.layer_paths.clone(),
        data_disk_path: Some(disk_guard.device()),
        vcpu_count: db_size.vcpu_count,
        mem_size_mib: db_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    // On start failure, release the fenced disk AWAITED (not via the Drop backstop) so an immediate
    // redeploy/re-wake can't race a fire-and-forget cleanup into a transient LeaseHeld/RwoUnsafe.
    let mut vm = match VmInstance::start(&db_id, &config, &runtime_dir).await {
        Ok(vm) => vm,
        Err(e) => {
            disk_guard.release().await;
            return Err(e);
        }
    };

    // Commit-to-Running: record the FC pid as the disk writer (FATAL — mirrors the app commit),
    // disarm the guard, and insert into the platform maps under the rendered id.
    let mut plat = platform.lock().await;
    let fc_pid = vm.pid();
    let (loop_dev, lease_epoch) = {
        if let Some(pid) = fc_pid
            && let Err(e) = dd.set_writer_pid(&db_id, disk_guard.token(), pid).await
        {
            drop(plat);
            let _ = vm.stop().await;
            disk_guard.release().await;
            return Err(anyhow::anyhow!("commit set_writer_pid {db_id}: {e}"));
        }
        let dev = disk_guard.device().to_string_lossy().into_owned();
        let epoch = disk_guard.token().epoch;
        plat.disk_tokens.insert(db_id.clone(), disk_guard.disarm());
        (Some(dev), Some(epoch))
    };
    plat.vms.insert(db_id.clone(), vm);
    plat.vm_states.insert(db_id.clone(), VmLifecycle::Running);
    plat.vm_incarnations.commit(&db_id);
    let ran_hash = plat.base_rootfs_hash.clone();
    plat.vm_rootfs_hashes
        .insert(db_id.clone(), ran_hash.clone());
    plat.wake_failures.remove(&db_id);
    // The DB VM's snapshot version token is the BASE project's deploy version: its metadata image is
    // rewritten every deploy (like the app's), so its snapshot is valid within a deploy version and
    // invalidated on redeploy (fail-open to a cold boot from the persistent data disk).
    let deployment_version = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    drop(plat);

    // Re-adoption record for the DB VM (role Db, derived from the rendered id); removed on teardown.
    write_handoff_record(
        &runtime_dir,
        &db_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        deployment_version,
    );

    // The DB VM is NOT proxy-routed (it's reached host-mediated); just wait for its agent to serve.
    wait_for_agent(&alloc.ip).await?;
    info!(project = %project_id, db_vm = %db_id, ip = %alloc.ip, "DB VM ready");
    Ok(())
}

/// One `boot_db_vm` call's share of [`PlatformState::db_boots`]: `boot_db_vm` increments under its
/// first lock section, this decrements on ANY exit (success, error, cancellation). Drop can't await
/// the async mutex, so the decrement is spawned (eventually-consistent) — a lagging decrement only
/// makes a concurrent drop answer Busy, the safe direction. Armed right after the increment.
pub(crate) struct DbBootGuard {
    platform: Arc<Mutex<PlatformState>>,
    db_id: String,
}

impl DbBootGuard {
    fn new(platform: Arc<Mutex<PlatformState>>, db_id: String) -> Self {
        Self { platform, db_id }
    }
}

impl Drop for DbBootGuard {
    fn drop(&mut self) {
        let platform = self.platform.clone();
        let id = self.db_id.clone();
        tokio::spawn(async move {
            let mut plat = platform.lock().await;
            if let Some(n) = plat.db_boots.get_mut(&id) {
                *n = n.saturating_sub(1);
                if *n == 0 {
                    plat.db_boots.remove(&id);
                }
            }
        });
    }
}

/// The DB-VM analogue of [`wait_for_route`]: a non-driver DB-reach request waits for the elected
/// wake driver to bring the DB VM to `Running`, then resolves its IP from the allocation (the DB VM
/// is never in the routing table — see the `wake_project_inner` commit). Fast-fails the moment the
/// driver leaves `Waking`/`Running` without success, so the reach caller retries promptly.
pub(crate) async fn wait_for_db_vm_running(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
) -> Result<String> {
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let p = platform.lock().await;
        match p.vm_states.get(project_id) {
            Some(VmLifecycle::Running) => {
                if let Ok(Some(a)) = p.store.get_vm_allocation(project_id) {
                    return Ok(a.ip);
                }
                drop(p);
                anyhow::bail!("DB VM {project_id} running but has no allocation");
            }
            Some(VmLifecycle::Waking) => {}
            _ => {
                drop(p);
                anyhow::bail!("wake of DB VM {project_id} did not complete; retry");
            }
        }
    }
    anyhow::bail!("timed out waiting for DB VM {project_id} to wake");
}
