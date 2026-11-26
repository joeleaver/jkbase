//! Tearing VMs and projects down: orphan cleanup at boot, full project teardown, dropping a
//! dedicated DB (and its sibling VM), and the force-stop path every failed lifecycle step falls back to.

use crate::{
    DISK_LEASE_TTL, PlatformState, VmLifecycle, handoff, reap_firecracker, release_data_disk,
    settle_superseded_hibernate, teardown_tap, unix_now, vm_identity,
};
use anyhow::Result;
use jkbase_control::store::{ProjectState, VmAllocation};
use jkbase_substrate::SubstrateError;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;

pub(crate) async fn cleanup_orphans(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let me_host = plat.host_id.clone();
    let allocs = match plat.store.list_vm_allocations() {
        Ok(a) => a,
        Err(_) => return,
    };

    for alloc in &allocs {
        // VM re-adoption §7: never reap a survivor re-adopted Running this start — adoption
        // already proved its liveness via the agent HTTP probe, and a momentarily-slow guest
        // could otherwise false-negative this 2s TCP probe and sever a live VM's allocation.
        if plat.vm_states.get(&alloc.project_id) == Some(&VmLifecycle::Running) {
            continue;
        }
        // Only probe our OWN VMs. A peer host's VM IP lives on its own network island,
        // unreachable from here, so a TCP probe would false-negative and wrongly reap a
        // live peer's allocation; peer/host liveness is via heartbeats (HOSTS), not TCP.
        // (Empty host_id = single-node / pre-placement = treat as local.)
        if !alloc.host_id.is_empty() && alloc.host_id != me_host {
            continue;
        }
        let reachable = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(format!("{}:80", alloc.ip)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        if !reachable {
            info!(
                project = %alloc.project_id,
                ip = %alloc.ip,
                "cleaning up orphaned allocation"
            );
            let _ = teardown_tap(&alloc.tap_device).await;
            let _ = plat.store.remove_vm_allocation(&alloc.project_id);
        }
    }
}

/// Fully reap a deleted project (the `teardown_callback` control invokes from
/// `DELETE /projects/{id}`): stop the VM, free its IP/TAP allocation, drop its
/// snapshot, and remove every on-disk artifact. Best-effort + idempotent — any
/// step that fails is reconciled by `reconcile_orphans_on_boot` on the next boot.
pub(crate) async fn handle_teardown(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
) -> Result<()> {
    // Reap under the platform lock, but only once no wake/hibernate is mid-flight for
    // this project: those drop the lock during the slow VM op, and destroying the disk
    // under a live restoring VM would free a loop device another project could reuse
    // (silent corruption). Wait it out (bounded ~30s), then do stop + release + destroy
    // in ONE locked section so a new wake can't interleave (it needs the lock to set
    // Waking).
    let (alloc, data_dir) = {
        let mut attempt = 0;
        loop {
            let mut plat = platform.lock().await;
            if attempt < 150
                && matches!(
                    plat.vm_states.get(project_id),
                    Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
                )
            {
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            if let Some(mut vm) = plat.vms.remove(project_id) {
                let _ = vm.stop().await;
            }
            plat.vm_incarnations.retire(project_id);
            // Force-kill ANY Firecracker for this project — including one a wake that
            // outlasted our wait-loop hasn't yet recorded in `vms` — BEFORE we destroy
            // the disk, so `destroy()` can never detach a loop device a live VM still
            // maps (which another project could then be handed = corruption). The wake,
            // finding its FC dead, fails and its guard releases.
            reap_firecracker(project_id).await;
            // The project is being deleted: drop its re-adoption record so a surviving FC
            // can't be re-adopted on a later start (remove_project_artifacts also nukes
            // run/{id} below; this is the explicit, lock-held removal beside disk_tokens).
            handoff::remove(&plat.data_dir.join("run"), project_id);
            // Release the data-disk lease + destroy the disk (detach loop device,
            // remove the image + holder record) as part of reaping the project.
            if let Some(token) = plat.disk_tokens.remove(project_id) {
                let ls = plat.lease.clone();
                let _ = ls.release(&token).await;
            }
            let dd = plat.data_disk.clone();
            let _ = dd.destroy(project_id).await;
            plat.vm_states.remove(project_id);
            plat.vm_rootfs_hashes.remove(project_id);
            let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();
            let _ = plat.store.remove_snapshot_meta(project_id);
            let _ = plat.store.remove_vm_allocation(project_id);
            // Free the project's L4 public ports, quarantining each so a stale client of the
            // torn-down tenant can't later be admitted into a reused port's new owner
            // [threat M1]. (The edge socket + firewall teardown land with the runtime relay.)
            for port in plat
                .store
                .list_port_allocations_for_project(project_id)
                .unwrap_or_default()
            {
                let _ = plat.store.quarantine_port(port.external_port, unix_now());
            }
            let _ = plat.store.remove_all_port_allocations(project_id);
            let _ = plat.store.delete_l4_transit_secret(project_id);
            break (alloc, plat.data_dir.clone());
        }
    };

    // Kill any leaked Firecracker that outlived the handle, then drop its TAP.
    let _ = tokio::process::Command::new("pkill")
        // Anchor to the EXACT api-sock path segment (/<id>/firecracker.sock), not an unanchored
        // `firecracker.*<id>` substring of the whole cmdline: project ids are user-chosen slugs
        // ([a-z0-9-]), and every FC cmdline carries `--api-sock .../run/<id>/firecracker.sock`, so
        // a short id like `a` matched as a substring would SIGKILL every tenant's FC host-wide
        // (cross-tenant kill). `<id>` is a single path segment bounded by `/`, so `/a/` never
        // matches `/ab/`. A rendered DB VM id (`{id}.db`) carries a `.` — itself an ERE
        // metacharacter — so `fc_sock_pkill_pattern` escapes every `.` in the id (else `foo.db`
        // would match `/fooadb/…` and cross-tenant-kill project `fooadb`).
        .args(["-f", &vm_identity::fc_sock_pkill_pattern(project_id)])
        .status()
        .await;
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    remove_project_artifacts(&data_dir, project_id).await;
    // Reap the sibling dedicated DB VM (`{id}.db`), if any — its VM handle, Firecracker, data disk,
    // lease, snapshot, IP/TAP allocation, and on-disk artifacts. Unconditional + idempotent: a
    // co-located or DB-less project has no `.db` VM, so every step no-ops; this also cleans up a
    // project that toggled dedicated→colocated (or a half-built dedicated deploy) leaving a stale
    // DB VM behind. Without it, deleting a dedicated project leaks its whole DB VM.
    teardown_db_vm_sibling(project_id, platform).await;
    info!(project = %project_id, "project torn down");
    Ok(())
}

/// The tenant's explicit drop of its dedicated DB (`DELETE /projects/{id}/db/dedicated`; the
/// control plane holds the per-project deploy lock around this). Reaps the sibling DB VM and its
/// `{id}.db.img` disk; the app VM and its disk (where a co-located DB lives) are never touched.
///
/// Unlike project teardown, the project lives on — DB wakes (gateway / `*.db` edge / console /
/// backup executors) keep arriving, and a wake-path cold boot runs `boot_db_vm` outside the deploy
/// lock. Destroying the disk under a boot that has fenced it but not yet started Firecracker would
/// let that FC boot on a freed loop device another project may since hold (cross-tenant write);
/// freeing the allocation under a boot that already read it would hand its IP/TAP to another VM.
/// So the reap happens in ONE locked section (no new wake can begin) and only when:
/// - no wake/hibernate of the DB VM is mid-flight (`Waking`/`Hibernating` — set and cleared only by
///   that driver, which holds the allocation from before its fence to its commit), waited out;
/// - no `boot_db_vm` is in flight ([`PlatformState::db_boots`]), likewise waited out;
/// - and the DISK LEASE is ours — the running DB VM's token (then nothing else can be fencing), or
///   one we acquire now (any fence in flight holds it ⇒ `LeaseHeld`). The lease is the actual
///   fence-exclusion invariant; the two checks above keep the allocation safe.
///
/// Anything still mid-flight after the wait ⇒ `Busy` with nothing touched (retryable 409).
pub(crate) async fn drop_dedicated_db(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
) -> Result<jkbase_control::api::DbDropOutcome> {
    use jkbase_control::api::DbDropOutcome;
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);
    let mut attempt = 0;
    let (alloc, data_dir) = loop {
        let mut plat = platform.lock().await;
        let in_flight = matches!(
            plat.vm_states.get(&db_id),
            Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
        ) || plat.db_boots.get(&db_id).is_some_and(|n| *n > 0);
        if in_flight {
            drop(plat);
            if attempt >= 150 {
                return Ok(DbDropOutcome::Busy);
            }
            attempt += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
            continue;
        }
        let present = plat.vms.contains_key(&db_id)
            || plat.store.get_vm_allocation(&db_id)?.is_some()
            || plat.data_disk.exists(&db_id).await.unwrap_or(false);
        if !present {
            return Ok(DbDropOutcome::NothingToDrop);
        }
        // Not running on our token ⇒ take the lease ourselves for the destroy, or stand down.
        let own_token = if plat.disk_tokens.contains_key(&db_id) {
            None
        } else {
            let (ls, hid) = (plat.lease.clone(), plat.host_id.clone());
            match ls.acquire(&db_id, &hid, DISK_LEASE_TTL).await {
                Ok(t) => Some(t),
                Err(SubstrateError::LeaseHeld { .. }) => {
                    return Ok(DbDropOutcome::Busy);
                }
                Err(e) => anyhow::bail!("lease acquire for {db_id}: {e}"),
            }
        };
        info!(project = %project_id, db_vm = %db_id, "dropping dedicated DB VM + disk (tenant request)");
        let reaped = reap_db_vm_locked(&mut plat, &db_id).await;
        if let Some(t) = own_token {
            let _ = plat.lease.release(&t).await;
        }
        break reaped;
    };
    finish_db_vm_teardown(&db_id, alloc, &data_dir).await;
    Ok(DbDropOutcome::Dropped)
}

/// Best-effort teardown of a project's **sibling DB VM** (`{project_id}.db`). Mirrors
/// [`handle_teardown`]'s reap keyed by the rendered DB id: stop the VM, hard-kill any surviving
/// Firecracker (BEFORE destroying its disk, so a live FC can't corrupt a reused loop device),
/// destroy the DB data disk + release its lease, drop lifecycle/snapshot state, free the IP/TAP,
/// and remove the on-disk artifacts. Idempotent and safe for a project with no DB VM (every step
/// no-ops). The rendered id's `.` is dot-escaped by [`vm_identity::fc_sock_pkill_pattern`], so the
/// pkill can never match a sibling tenant's Firecracker.
pub(crate) async fn teardown_db_vm_sibling(project_id: &str, platform: &Arc<Mutex<PlatformState>>) {
    let db_id = vm_identity::vm_id(project_id, vm_identity::VmRole::Db);
    let (alloc, data_dir) = {
        let mut plat = platform.lock().await;
        reap_db_vm_locked(&mut plat, &db_id).await
    };
    finish_db_vm_teardown(&db_id, alloc, &data_dir).await;
}

/// The locked half of [`teardown_db_vm_sibling`]: stop + hard-kill the DB VM, release its lease,
/// destroy its disk, drop its lifecycle/snapshot/allocation rows. Runs in ONE locked section so no
/// wake can interleave (a wake needs the lock to set `Waking`). Returns what the unlocked
/// [`finish_db_vm_teardown`] needs.
pub(crate) async fn reap_db_vm_locked(
    plat: &mut PlatformState,
    db_id: &str,
) -> (Option<VmAllocation>, PathBuf) {
    if let Some(mut vm) = plat.vms.remove(db_id) {
        let _ = vm.stop().await;
    }
    plat.vm_incarnations.retire(db_id);
    // Kill any DB Firecracker not tracked in `vms` BEFORE destroying its disk.
    reap_firecracker(db_id).await;
    handoff::remove(&plat.data_dir.join("run"), db_id);
    if let Some(token) = plat.disk_tokens.remove(db_id) {
        let ls = plat.lease.clone();
        let _ = ls.release(&token).await;
    }
    let dd = plat.data_disk.clone();
    let _ = dd.destroy(db_id).await;
    plat.vm_states.remove(db_id);
    plat.vm_rootfs_hashes.remove(db_id);
    plat.wake_failures.remove(db_id);
    let alloc = plat.store.get_vm_allocation(db_id).ok().flatten();
    let _ = plat.store.remove_snapshot_meta(db_id);
    let _ = plat.store.remove_vm_allocation(db_id);
    (alloc, plat.data_dir.clone())
}

/// The unlocked half of [`teardown_db_vm_sibling`]: free the TAP + remove on-disk artifacts.
pub(crate) async fn finish_db_vm_teardown(
    db_id: &str,
    alloc: Option<VmAllocation>,
    data_dir: &Path,
) {
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    // `remove_project_artifacts` for a `.db` id clears content-images/`{id}.db.ext4`,
    // data-disks/`{id}.db.{img,holder}`, snapshots/`{id}.db`, run/`{id}.db`; the base-only trees
    // (hosting/builds/git/buildcache/`{id}.db`) simply don't exist → no-ops.
    remove_project_artifacts(data_dir, db_id).await;
}

/// Remove every per-project on-disk artifact (content image, data disk, snapshot,
/// run dir, hosting tree, build workspace). Best-effort; absent paths are ignored.
pub(crate) async fn remove_project_artifacts(data_dir: &Path, project_id: &str) {
    let _ = tokio::fs::remove_file(
        data_dir
            .join("content-images")
            .join(format!("{project_id}.ext4")),
    )
    .await;
    // Data disk: legacy `.ext4` plus the loop-managed `.img` + its holder record.
    let disks = data_dir.join("data-disks");
    for f in [
        format!("{project_id}.ext4"),
        format!("{project_id}.img"),
        format!("{project_id}.holder"),
    ] {
        let _ = tokio::fs::remove_file(disks.join(f)).await;
    }
    for dir in ["snapshots", "run", "hosting", "builds", "buildcache"] {
        // `buildcache/{id}/` holds the per-(project,language) warm-cache images.
        // Purge on delete so a recreated same-name project can't inherit the prior
        // tenant's cache (same isolation rule as secrets/data — the project id IS the
        // slug, so a reused name would otherwise read another tenant's build cache).
        let _ = tokio::fs::remove_dir_all(data_dir.join(dir).join(project_id)).await;
    }
    // Per-project git bare repo (build·D push-to-deploy): `git/{id}.git`.
    let _ = tokio::fs::remove_dir_all(data_dir.join("git").join(format!("{project_id}.git"))).await;
}

/// Centralized force-stop + state reconciliation for a project whose graceful
/// hibernate could not complete (wedged agent, pause/snapshot timeout, or error).
/// Idempotent and best-effort: every step is independently fallible-ignored so a
/// failure in one does not strand the others. After this runs the project is left
/// as Hibernated-with-no-snapshot, so the next request cold-boots cleanly.
///
/// `incarnation`: `Some(n)` when acting for a specific VM (a hibernate that dropped the lock) —
/// if `n` is no longer current, a newer incarnation (or a teardown) owns the id and this only
/// settles our own leftover `Hibernating` ([`settle_superseded_hibernate`]): the pkill/TAP-teardown/
/// token-release below are id-keyed and would hit the NEWER VM. The caller has already stopped its
/// own FC. `None` = unconditional (the shutdown last resort).
pub(crate) async fn force_stop_and_cleanup(
    project_id: &str,
    platform: &Arc<Mutex<PlatformState>>,
    incarnation: Option<u64>,
) {
    let mut plat = platform.lock().await;
    if let Some(n) = incarnation
        && !plat.vm_incarnations.is_current(project_id, n)
    {
        tracing::warn!(project = %project_id,
            "VM superseded mid-hibernate; skipping force-stop cleanup of the newer incarnation");
        settle_superseded_hibernate(&mut plat, project_id);
        return;
    }

    // The VM handle may already be gone (hibernate_project removes it before the
    // pause that fails) — stop() it if present, but don't rely on it.
    if let Some(mut vm) = plat.vms.remove(project_id) {
        let _ = vm.stop().await;
    }
    plat.vm_incarnations.retire(project_id);
    plat.vm_rootfs_hashes.remove(project_id);
    // The FC is being reaped below — drop its re-adoption record so a later start can't adopt it.
    // (hibernate_project already removed it before its pause; idempotent if so.)
    handoff::remove(&plat.data_dir.join("run"), project_id);

    // Everything id-keyed — the FC kill, the disk release, the TAP teardown — runs UNDER the lock
    // and BEFORE `Hibernated` is published below: deploy / boot_db_vm / wake treat `Hibernated` as
    // settled and proceed, so a kill or TAP teardown still pending after it could land on the NEXT
    // incarnation's FC/TAP (same socket path, same TAP name). Kill first, then release the disk.
    //
    // Guarantee the leaked Firecracker process dies even when `vms` had no handle.
    let _ = tokio::process::Command::new("pkill")
        // Anchor to the EXACT api-sock path segment (/<id>/firecracker.sock), not an unanchored
        // `firecracker.*<id>` substring of the whole cmdline: project ids are user-chosen slugs
        // ([a-z0-9-]), and every FC cmdline carries `--api-sock .../run/<id>/firecracker.sock`, so
        // a short id like `a` matched as a substring would SIGKILL every tenant's FC host-wide
        // (cross-tenant kill). `<id>` is a single path segment bounded by `/`, so `/a/` never
        // matches `/ab/`. A rendered DB VM id (`{id}.db`) carries a `.` — itself an ERE
        // metacharacter — so `fc_sock_pkill_pattern` escapes every `.` in the id (else `foo.db`
        // would match `/fooadb/…` and cross-tenant-kill project `fooadb`).
        .args(["-f", &vm_identity::fc_sock_pkill_pattern(project_id)])
        .status()
        .await;

    // Release the data-disk hold so the next wake re-fences.
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    // Tear down TAP so cleanup_orphans reconciles consistently on next boot (a
    // leaked-but-listening process would otherwise read as "reachable" and the
    // stale allocation would never be reaped). wake re-runs setup_tap.
    if let Ok(Some(a)) = plat.store.get_vm_allocation(project_id) {
        let _ = teardown_tap(&a.tap_device).await;
    }

    // Drop any snapshot meta so wake deterministically cold-boots rather than
    // trying to restore a stale or half-written snapshot.
    let _ = plat.store.remove_snapshot_meta(project_id);

    // Persisted state -> Hibernated keeps the project's domains routed so the next
    // request cold-boots cleanly (snapshot is gone, so wake falls through to boot).
    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        let _ = plat.store.update_project(&proj);
    }

    // Never leave it stuck at Hibernating (shared with the idle loop — that would
    // make wake_project spin and bail on every subsequent request).
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);
}
