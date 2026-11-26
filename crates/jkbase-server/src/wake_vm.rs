//! The body of a wake, run by the task that won the single-flight election in [`crate::wake`]:
//! restore the VM from its snapshot when that is viable, else cold-boot it, then commit it to Running.

use crate::{
    LogShipper, PlatformState, RUNTIME_CGROUP_PARENT, VmLifecycle, WAKE_BACKOFF, WakingGuard,
    check_project_has_database, check_project_has_volumes, data_disk_mib, disk_cap_bytes,
    fence_data_disk, handle_deploy, handoff, layer_plan, project_is_dedicated,
    register_active_routes, resync_clock_agent, setup_tap, snapshot_restore_decision, vm_identity,
    wait_for_agent, wait_for_db_vm_running, wait_for_route, write_handoff_record,
};
use anyhow::Result;
use jkbase_control::store::ProjectState;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::DomainMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;

pub(crate) async fn wake_project_inner(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<String> {
    let mut plat = platform.lock().await;

    // Throttle a project that just failed to wake: fast-fail (the proxy retries) within
    // WAKE_BACKOFF, so continuous traffic at a broken/doomed project can't spin unbounded full
    // boot attempts — each of which bumps the data-disk lease epoch and spawns Firecracker(s).
    if let Some(t) = plat.wake_failures.get(project_id)
        && t.elapsed() < WAKE_BACKOFF
    {
        drop(plat);
        anyhow::bail!("project {project_id} recently failed to wake; retry shortly");
    }

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Hibernated) => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
        Some(VmLifecycle::Waking) => {
            drop(plat);
            // A DB VM is never proxy-routed (§ security: a routing-table entry would expose it via a
            // `foo.db.jkbase.app` Host), so a concurrent waiter waits on its lifecycle and resolves
            // its IP from the allocation, not the routing table. An app VM waits for its route.
            if vm_identity::split_vm_id(project_id).1 == vm_identity::VmRole::Db {
                return wait_for_db_vm_running(project_id, &platform).await;
            }
            return wait_for_route(project_id, &platform, &routing).await;
        }
        Some(VmLifecycle::Running) => {
            if vm_identity::split_vm_id(project_id).1 == vm_identity::VmRole::Db {
                // Not in the routing table by design; the allocation is the DB VM's stable address.
                if let Ok(Some(a)) = plat.store.get_vm_allocation(project_id) {
                    return Ok(a.ip);
                }
                anyhow::bail!("DB VM {project_id} running but has no allocation");
            }
            let table = routing.read().await;
            if let Some(ip) = table.get(project_id) {
                return Ok(ip.clone());
            }
            anyhow::bail!("VM running but not in routing table");
        }
        Some(VmLifecycle::Hibernating) => {
            // Wait for hibernation to complete, then wake
            drop(plat);
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let p = platform.lock().await;
                if p.vm_states.get(project_id) == Some(&VmLifecycle::Hibernated) {
                    drop(p);
                    return Box::pin(wake_project_inner(
                        project_id,
                        platform.clone(),
                        routing,
                        domain_map,
                        shipper,
                    ))
                    .await;
                }
            }
            anyhow::bail!("timed out waiting for {project_id} to finish hibernating");
        }
        None => {
            // No lifecycle state — cold boot
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
    }

    // We are now the elected wake driver in `Waking`. This guard resets that state on ANY exit
    // that doesn't reach `Running` — including a client-disconnect cancellation that DROPS this
    // future mid-boot, and every early `?` below — so the project can never get stuck `Waking`
    // (the nlnwt brick). The success path `commit()`s it.
    let waking_guard = WakingGuard::new(platform.clone(), project_id.to_string());

    // Try snapshot restore first, fall back to cold boot
    let snap_meta = plat.store.get_snapshot_meta(project_id)?;

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(a) => a,
        None => {
            // No allocation — need full cold boot via handle_deploy (which drives its own
            // lifecycle); drop our Waking driver state and disarm the guard so it no-ops.
            plat.vm_states.remove(project_id);
            drop(plat);
            waking_guard.commit();
            info!(project = %project_id, "no allocation, cold booting");
            let routing_clone = routing.clone();
            handle_deploy(project_id, platform, routing, domain_map, shipper).await?;
            let table = routing_clone.read().await;
            return table
                .get(project_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("cold boot completed but no route"));
        }
    };

    // The metadata image already exists from deploy (with `_layers.json` baked in);
    // wake reuses it as-is — no rebuild.
    let metadata_image_path = plat
        .data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));

    // Decide restore-vs-cold-boot while we still hold the lock (needs the store + data_dir). A
    // restore is byte-correct ONLY if the snapshot stamps the rootfs it ACTUALLY ran (valid hex,
    // its immutable CAS blob still present) AND its deployment version still matches the project's
    // current version (so the metadata image + erofs layers it bakes by fixed path are the
    // current, coherent set). Anything else fails OPEN to a clean cold boot from the current
    // rootfs — never a brick. The reason becomes the `wake_outcome` so a post-deploy spike in
    // cold-boot fallbacks (e.g. a bad staged rootfs) is visible instead of silent.
    // Per-role/-tier identity: a dedicated DB VM (`{id}.db`) reuses its BASE project's deployment
    // for every store/content read (it has no `hosting/<id>.db/`), so the snapshot version gate
    // (and thus fast-restore) works. A co-located app VM is unchanged (base == project_id).
    let (base_pid, vm_role) = vm_identity::split_vm_id(project_id);
    let dedicated = project_is_dedicated(&plat.data_dir, base_pid);
    let current_version = plat
        .store
        .get_project(base_pid)
        .ok()
        .flatten()
        .and_then(|p| p.current_version);
    let current_rootfs_hash = plat.base_rootfs_hash.clone();
    let cas_dir = plat.data_dir.join("base-rootfs");
    let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
    let (mut restore_hash, mut nonviable_outcome) =
        snapshot_restore_decision(snap_meta.as_ref(), current_version, &cas_dir);

    // Whether this VM has a data disk, plus clones of the RWO substrate so the fence (below) can
    // run AFTER dropping the platform lock. The DB VM ALWAYS has one; a dedicated project's app VM
    // must NOT fence a disk on account of the DB (it runs in the sibling VM) — only for its own
    // volumes or a disk it already owns (e.g. a colocated→dedicated migration keeps `{id}.img`).
    let has_disk = match vm_role {
        vm_identity::VmRole::Db => true,
        vm_identity::VmRole::App => {
            check_project_has_volumes(&plat.data_dir, base_pid)
                || (!dedicated && check_project_has_database(&plat.data_dir, base_pid))
                || plat.data_disk.exists(project_id).await.unwrap_or(false)
        }
    };
    let dd = plat.data_disk.clone();
    let disk_cap = disk_cap_bytes(&plat.store, base_pid);
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();
    let data_dir = plat.data_dir.clone();

    // The erofs layer attach order for the cold-boot fallback (restore re-derives
    // drives from the snapshot, so this only matters when restore fails/misses). Read
    // the sidecar PAIRED with the metadata image — NOT a recompute from `live`, which
    // can drift from the (last successfully built) image's baked `_layers.json` and
    // mis-assign device letters. Absent ⇒ legacy/static image with no layers.
    let layer_paths = layer_plan::read_layer_paths(&metadata_image_path);

    // Size by ROLE: an app VM wakes at App sizing (unchanged), a dedicated DB VM (`{id}.db`) at
    // the lean DB sizing. A restore reads the size back from `SnapshotMeta`, which was stamped at
    // hibernate from this SAME `vm_size_for`, so the snapshot and restore sizes can't drift.
    let vm_size = vm_identity::vm_size_for(vm_identity::split_vm_id(project_id).1);
    let mut config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path: plat.base_rootfs_path.clone(),
        metadata_image_path: Some(metadata_image_path),
        layer_paths,
        data_disk_path: None,
        vcpu_count: vm_size.vcpu_count,
        mem_size_mib: vm_size.mem_size_mib,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
        runtime_cgroup_parent: Some(PathBuf::from(RUNTIME_CGROUP_PARENT)),
    };
    let runtime_dir = plat.data_dir.join("run");
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Fence the data disk read-write-once BEFORE restore/boot, so the restored guest
    // — which would otherwise re-derive the RW data drive straight from the snapshot,
    // bypassing the gate — only ever writes through the exclusivity attach. The
    // restore path patches the data drive to this fenced device; refuse→cold-boot
    // (reap + retry, else error) lives in fence_data_disk. None when no data disk.
    let disk_guard = if has_disk {
        // Sized from the BASE project's `_database.json` ([database].size) — the DB VM has no
        // `hosting/<id>.db/` — within the project-wide budget; fenced under the RENDERED id.
        let holds_db = vm_role == vm_identity::VmRole::Db || !dedicated;
        let disk_mib = data_disk_mib(&data_dir, project_id, holds_db, disk_cap).await;
        let g = fence_data_disk(&dd, &ls, &hid, project_id, disk_mib).await?;
        config.data_disk_path = Some(g.device());
        // A grown disk can't be restored onto: the snapshot's guest believes the old size and
        // would never grow its fs. Drop the snapshot and cold-boot (the agent grows at mount).
        if g.grown && restore_hash.is_some() {
            restore_hash = None;
            nonviable_outcome = "skipped_disk_grown";
            let _ = platform.lock().await.store.remove_snapshot_meta(project_id);
            let _ = tokio::fs::remove_dir_all(&snapshot_dir).await;
        }
        Some(g)
    } else {
        None
    };

    // Boot (restore-or-cold) + agent readiness, fenced by `disk_guard`. Returns the VM, the
    // rootfs hash it ACTUALLY ran (stamped into the next snapshot), and a `wake_outcome` for
    // observability. On Err we release the fenced disk + lease AWAITED (not via the Drop
    // backstop) so a re-wake/re-deploy can't race a fire-and-forget cleanup and fail transiently
    // with LeaseHeld/RwoUnsafe.
    let boot: Result<(VmInstance, String, &'static str)> = async {
        // Cold boot the CURRENT rootfs; shared by the non-viable path and the restore fallbacks.
        // Reuses the already-held `disk_guard` (config.data_disk_path) — never re-fences — so a
        // restore fallback can't self-deadlock against its own just-released lease.
        async fn cold_boot(
            project_id: &str,
            config: &VmConfig,
            runtime_dir: &Path,
            agent_ip: &str,
            current_hash: &str,
            outcome: &'static str,
        ) -> Result<(VmInstance, String, &'static str)> {
            let mut vm = VmInstance::start(project_id, config, runtime_dir).await?;
            // Synchronous-to-death on agent-wait failure, mirroring the restore arm's
            // `restored.stop().await`: a bare `?` here would drop `vm` (SIGKILL via Drop, NOT
            // awaited), so the caller's `disk_guard.release()` could `losetup -d` the data disk
            // out from under a still-dying FC. `stop()` reaps the FC before we return Err.
            if let Err(e) = wait_for_agent(agent_ip).await {
                let _ = vm.stop().await;
                return Err(e);
            }
            Ok((vm, current_hash.to_string(), outcome))
        }

        let (vm, ran_hash, outcome) = if let (Some(meta), Some(hash)) =
            (snap_meta.as_ref(), restore_hash.as_ref())
        {
            let snap_path = PathBuf::from(&meta.snapshot_path);
            let mem_path = PathBuf::from(&meta.mem_file_path);
            info!(project = %project_id, "restoring from snapshot");
            match VmInstance::restore_from_snapshot(
                project_id,
                &config,
                &runtime_dir,
                &snap_path,
                &mem_path,
            )
            .await
            {
                Ok(mut restored) => match wait_for_agent(&alloc.ip).await {
                    Ok(()) => (restored, hash.clone(), "restored"),
                    Err(e) => {
                        // Restore resumed the guest but its agent never came ready (corrupt/wedged
                        // snapshot, or a tenant pinned hostile RAM before hibernate). Synchronously
                        // REAP the restored FC (stop = SIGKILL + waitpid, so it releases the fenced
                        // data loop BEFORE the cold boot reopens it — never two Firecrackers on one
                        // RWO disk), POISON the snapshot (so subsequent wakes cold-boot directly
                        // rather than repeating this ~10s+ cycle every wake), then cold-boot the
                        // current rootfs reusing the held fence.
                        tracing::warn!(project = %project_id, error = %e, "restored VM agent not ready; reaping + poisoning snapshot + cold booting");
                        // The whole no-double-writer guarantee rests on FC1 being dead before the
                        // cold boot reopens the fenced loop — surface (don't swallow) a reap error.
                        if let Err(re) = restored.stop().await {
                            tracing::warn!(project = %project_id, error = %re, "reap of restored FC before cold boot reported an error");
                        }
                        {
                            let p = platform.lock().await;
                            let _ = p.store.remove_snapshot_meta(project_id);
                        }
                        let _ = tokio::fs::remove_dir_all(&snapshot_dir).await;
                        cold_boot(
                            project_id,
                            &config,
                            &runtime_dir,
                            &alloc.ip,
                            &current_rootfs_hash,
                            "restore_ok_agent_fail_coldboot",
                        )
                        .await?
                    }
                },
                Err(e) => {
                    tracing::warn!(project = %project_id, error = %e, "snapshot restore failed, cold booting");
                    // Defensive cleanup of a half-spawned restore FC, by EXACT socket path —
                    // never a `pkill -f firecracker.*{id}` substring (which could reap a project
                    // whose id contains this one).
                    let failed_sock = runtime_dir.join(project_id).join("firecracker.sock");
                    if failed_sock.exists() {
                        let _ = tokio::fs::remove_file(&failed_sock).await;
                    }
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    cold_boot(
                        project_id,
                        &config,
                        &runtime_dir,
                        &alloc.ip,
                        &current_rootfs_hash,
                        "restore_failed_coldboot",
                    )
                    .await?
                }
            }
        } else {
            info!(project = %project_id, reason = nonviable_outcome, "cold booting (no viable snapshot)");
            cold_boot(
                project_id,
                &config,
                &runtime_dir,
                &alloc.ip,
                &current_rootfs_hash,
                nonviable_outcome,
            )
            .await?
        };

        // A restored snapshot resumes with its wall clock frozen at snapshot time, so
        // it lags by the whole hibernation; a cold boot's tsc clock is undisciplined.
        // Nudge the agent to re-read its KVM PTP reference and step CLOCK_REALTIME now,
        // so the first request after wake sees correct time instead of waiting for the
        // agent's periodic discipline tick. Best-effort — never fail a wake on this.
        resync_clock_agent(&alloc.ip).await;
        Ok((vm, ran_hash, outcome))
    }
    .await;
    let (mut vm, ran_hash, outcome) = match boot {
        Ok(t) => t,
        Err(e) => {
            // Release the fenced disk AWAITED, THEN record the failure. Ordering matters: the
            // disk is fully released before the next request can re-fence, so the retry doesn't
            // hit a transient LeaseHeld/RwoUnsafe. `waking_guard` (dropped on return) resets the
            // `Waking` state so the project isn't bricked.
            if let Some(g) = disk_guard {
                g.release().await;
            }
            let mut p = platform.lock().await;
            p.wake_failures
                .insert(project_id.to_string(), std::time::Instant::now());
            drop(p);
            return Err(e);
        }
    };

    let mut plat = platform.lock().await;

    // Re-validate the project still exists before committing the VM. handle_teardown
    // waits out our `Waking` state, so a delete can't race the body above — but a
    // delete that landed BEFORE we set Waking would leave us booting a ghost. If so,
    // abort: SIGKILL the FC (drop `vm`) FIRST, then release the guard AWAITED — not via
    // the fire-and-forget Drop backstop, whose deferred detach could later `losetup -d`
    // a recreated same-slug VM's live device. Drop the platform lock first so the
    // release's losetup I/O isn't held under the mutex.
    //
    // Look up the BASE project: a dedicated DB VM (`{id}.db`) has no project row of its own, so
    // checking the rendered id aborted EVERY DB-VM wake as "deleted" — a hibernated DB VM could
    // never come back short of a redeploy, and each attempt was a full unthrottled FC boot.
    if plat.store.get_project(base_pid).ok().flatten().is_none() {
        plat.vm_states.remove(project_id);
        plat.vm_rootfs_hashes.remove(project_id);
        // Throttle like any failed wake, so traffic at a deleted project can't drive serial boots.
        plat.wake_failures
            .insert(project_id.to_string(), std::time::Instant::now());
        drop(plat);
        let _ = vm.stop().await; // synchronous-to-death before detaching the disk it maps
        if let Some(g) = disk_guard {
            g.release().await; // detach + lease release inline; disarms so Drop no-ops
        }
        // No handoff was written this wake (that happens at commit, below), but a stale one
        // from a prior incarnation must not survive a delete-during-wake — remove defensively.
        handoff::remove(&runtime_dir, project_id);
        anyhow::bail!("project {project_id} was deleted during wake; aborting");
    }

    // Record Firecracker's PID as the data-disk writer (FATAL — see the deploy commit), capture
    // the fence facts for the handoff, then DISARM the guard and hold the token for the VM's
    // lifetime (released on hibernate/stop/teardown).
    let fc_pid = vm.pid();
    let (loop_dev, lease_epoch) = if let Some(guard) = disk_guard {
        if let Some(pid) = fc_pid {
            let dd2 = plat.data_disk.clone();
            if let Err(e) = dd2.set_writer_pid(project_id, guard.token(), pid).await {
                drop(plat);
                // Kill the FC synchronously-to-death BEFORE releasing (detaching) the disk it maps.
                let _ = vm.stop().await;
                guard.release().await;
                let mut p = platform.lock().await;
                p.wake_failures
                    .insert(project_id.to_string(), std::time::Instant::now());
                drop(p);
                return Err(anyhow::anyhow!("commit set_writer_pid {project_id}: {e}"));
            }
        }
        let dev = guard.device().to_string_lossy().into_owned();
        let epoch = guard.token().epoch;
        plat.disk_tokens
            .insert(project_id.to_string(), guard.disarm());
        (Some(dev), Some(epoch))
    } else {
        (None, None)
    };
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);
    plat.vm_incarnations.commit(project_id);
    // Track the rootfs this VM actually ran so the NEXT hibernate stamps the truthful hash
    // (a restored VM ran the OLD blob, not `current`). Clear any prior wake-failure throttle.
    plat.vm_rootfs_hashes
        .insert(project_id.to_string(), ran_hash.clone());
    plat.wake_failures.remove(project_id);

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Active;
        plat.store.update_project(&proj)?;
    }
    drop(plat);
    waking_guard.commit();

    // Persist the re-adoption record (mirrors the deploy commit; removed on every teardown).
    write_handoff_record(
        &runtime_dir,
        project_id,
        fc_pid,
        &alloc,
        loop_dev,
        lease_epoch,
        ran_hash,
        current_version,
    );

    // A DB VM is reached host-mediated only; it must NOT enter the routing table (a `foo.db` entry
    // would be reachable via a `foo.db.jkbase.app` Host). Its address is the allocation IP, returned
    // below. App VMs register their fast-path route + domains as before.
    if vm_identity::split_vm_id(project_id).1 != vm_identity::VmRole::Db {
        register_active_routes(
            &routing,
            &domain_map,
            &active_domains,
            project_id,
            &alloc.ip,
        )
        .await;
    }

    info!(project = %project_id, ip = %alloc.ip, wake_outcome = outcome, "VM awake");
    Ok(alloc.ip)
}
