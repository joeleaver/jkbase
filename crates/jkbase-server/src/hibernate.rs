//! Hibernation: snapshot a running VM (or stop it when a snapshot is not viable), release its data
//! disk and routes, and leave it wakeable. Races with a concurrent redeploy are settled through the
//! VM incarnation marker.

use crate::{
    LogShipper, PlatformState, VmLifecycle, agent_alive, force_stop_and_cleanup, handoff,
    release_data_disk, settle_superseded_hibernate, vm_identity,
};
use anyhow::Result;
use jkbase_control::store::{ProjectState, SnapshotMeta};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;

pub(crate) async fn hibernate_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    // Idle-path callers pass the DB relay registry + L4 plane so we can re-check for a LIVE
    // managed-DB relay / L4 established flow UNDER the platform lock (§5/§3(d)); shutdown/quota
    // callers pass `None` — those paths hibernate regardless (relays are force-closed on drain;
    // over-quota must win).
    db_registry: Option<&Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
    l4_plane: Option<&Arc<jkbase_proxy::l4_plane::L4Plane>>,
) -> Result<()> {
    let mut plat = platform.lock().await;

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Running) => {
            // §5: re-check under the platform lock that no live DB relay appeared since the
            // idle loop's UNLOCKED conn_count read (db_ingress reserves the relay before its
            // wake, so a racing connection is already counted here) — otherwise a byte-silent
            // realtime subscription would be hibernated out from under itself. A relay that
            // slips in during this function's own critical section instead fails its bounded
            // connect and the client retries, waking the VM cleanly.
            if db_registry
                .map(|r| r.conn_count(vm_identity::base_project_id(project_id)) > 0)
                .unwrap_or(false)
            {
                return Ok(());
            }
            // §3(d): symmetric L4 re-check — an ESTABLISHED L4 flow that promoted since the idle
            // loop's unlocked read keeps the VM warm, so a live UDP session isn't snapshotted
            // mid-stream. Provisional flows deliberately don't count (they can't pin warm).
            if l4_plane
                .map(|p| p.conn_count(vm_identity::base_project_id(project_id)) > 0)
                .unwrap_or(false)
            {
                return Ok(());
            }
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Hibernating);
        }
        _ => anyhow::bail!("project {project_id} is not running"),
    }

    // Remove from the routes fast-path first (new requests will trigger wake).
    // Leave the domain map intact so hibernated hosts still resolve + wake.
    {
        let mut table = routing.write().await;
        table.remove(project_id);
        if let Ok(domains) = plat.store.list_active_domains_for_project(project_id) {
            for d in &domains {
                table.remove(&d.host);
            }
        }
    }

    let mut vm = match plat.vms.remove(project_id) {
        Some(vm) => vm,
        None => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Running);
            anyhow::bail!("no VM instance for {project_id}");
        }
    };
    // Pin the incarnation we're hibernating: we drop the lock below for the pause+snapshot, and
    // every later state write (here and in `force_stop_and_cleanup`) is gated on it still being
    // current — a supersede in that window owns the id's state from then on, not us.
    let incarnation = plat.vm_incarnations.capture(project_id);

    // VM re-adoption §6/R4: remove the handoff record FIRST — before the pause below — so even a
    // SIGKILL of this server mid-snapshot can't leave a PAUSED FC that the next start would
    // re-adopt as "running" (the paused-FC-resurrection hole). Decoupled from the disk_tokens
    // clear, which is in the SECOND lock after the pause. The teardown paths that have no pause
    // (force-stop / self-fence / teardown) remove it beside their disk_tokens clear instead.
    handoff::remove(&plat.data_dir.join("run"), project_id);

    let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
    let agent_ip = plat
        .store
        .get_vm_allocation(project_id)
        .ok()
        .flatten()
        .map(|a| a.ip);
    drop(plat);

    // Pre-pause wedge detection: if the agent is unreachable/wedged, skip the
    // flush + pause/snapshot entirely and go straight to a clean force-stop. A
    // wedged guest can't complete a Firecracker Pause+snapshot anyway, and
    // attempting it is what produces the "failed to pause VM" stall.
    let wedged = match &agent_ip {
        Some(ip) => !agent_alive(ip).await,
        None => true, // no allocation/ip -> nothing to pause cleanly
    };
    if wedged {
        tracing::warn!(project = %project_id, "agent unreachable/wedged, force-stopping instead of hibernating");
        // Kill OUR FC synchronously-to-death first (as the snapshot-failure arms do): the cleanup
        // below finds no `vms` handle (we took it) and stands down entirely if we've been
        // superseded, so it can't be relied on to reap this FC — and a bare drop() of an Adopted
        // survivor wouldn't kill it at all.
        let _ = vm.stop().await;
        force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
        return Ok(());
    }

    // Final flush of the agent's buffer before we pause it. Bounded so a wedged
    // agent (that passed the probe but then stalls) can't block shutdown.
    if let Some(ip) = &agent_ip {
        let _ = tokio::time::timeout(Duration::from_secs(3), shipper.ship(project_id, ip)).await;
    }

    // Bound pause+snapshot so one bad VM can't stall the drain of the rest. The
    // budget is generous because snapshotting a 1 GiB mem file is legit slow I/O
    // (Pause itself is sub-second). Any timeout or error -> clean force-stop.
    let (snapshot_path, mem_file_path) = match tokio::time::timeout(
        Duration::from_secs(60),
        vm.hibernate(&snapshot_dir),
    )
    .await
    {
        Ok(Ok(paths)) => paths,
        Ok(Err(e)) => {
            tracing::error!(project = %project_id, error = %e, "hibernate failed, force-stopping");
            // stop() is synchronous-to-death for BOTH variants; a bare drop() would NOT kill an
            // Adopted survivor (its Drop is a no-op), leaving force_stop to detach the loop under a
            // live FC. Kill here so the FC is gone before force_stop releases the disk.
            let _ = vm.stop().await;
            force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
            return Ok(());
        }
        Err(_elapsed) => {
            tracing::error!(project = %project_id, "hibernate timed out (VM wedged), force-stopping");
            let _ = vm.stop().await;
            force_stop_and_cleanup(project_id, &platform, Some(incarnation)).await;
            return Ok(());
        }
    };

    let mut plat = platform.lock().await;

    // Superseded mid-snapshot (redeploy / teardown / self-fence retired our incarnation while the
    // lock was down): the id's disk token, VM handle, lifecycle and snapshot meta are no longer
    // ours. Our FC is already dead (hibernate kills it), so touch nothing else — releasing the token
    // would detach a newer live FC's disk, and `Hibernated` + this snapshot would clobber its
    // `Running` and later restore stale RAM against its disk. The snapshot files we just wrote
    // are inert without meta (a wake only restores via meta).
    if !plat.vm_incarnations.is_current(project_id, incarnation) {
        tracing::warn!(project = %project_id,
            "VM superseded mid-hibernate; leaving the newer incarnation's state untouched");
        settle_superseded_hibernate(&mut plat, project_id);
        return Ok(());
    }

    // The VM is down (hibernate killed the FC); release its data-disk hold NOW —
    // before persisting snapshot meta — so a persistence error can't leak the lease
    // (which would wedge the project in Hibernating + LeaseHeld on the next wake). The
    // image file persists; the next wake re-fences + the restore patches the drive.
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    // Stamp the snapshot with what the restore will byte-depend on: the rootfs the VM was
    // ACTUALLY mapped against (NOT the process's current hash — a restored-then-rehibernated VM
    // runs the OLD blob), and the deployment version (gates the metadata image + layers, which
    // are rebuilt-in-place per deploy and snapshot-baked by fixed path). Either being absent on
    // the next wake ⇒ non-viable ⇒ fail open to a clean cold boot. Drop the per-VM hash now: the
    // VM is down.
    let base_rootfs_hash = plat.vm_rootfs_hashes.remove(project_id);
    // Version-gate token from the BASE project (a DB VM has no project row of its own), so a DB
    // VM's snapshot is stamped with — and on wake compared against — the same deploy version its
    // metadata image was built at, keeping fast-restore viable within a deploy version.
    let deployment_version = plat
        .store
        .get_project(vm_identity::base_project_id(project_id))
        .ok()
        .flatten()
        .and_then(|p| p.current_version);

    // Stamp the snapshot with THIS VM's role-derived size so the restore (which reads these
    // fields back) maps the mem file at the identical geometry — an app VM at App sizing, a
    // dedicated DB VM at DB sizing.
    let snap_size = vm_identity::vm_size_for(vm_identity::split_vm_id(project_id).1);
    let meta = SnapshotMeta {
        project_id: project_id.to_string(),
        snapshot_path: snapshot_path.to_string_lossy().to_string(),
        mem_file_path: mem_file_path.to_string_lossy().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        vcpu_count: snap_size.vcpu_count,
        mem_size_mib: snap_size.mem_size_mib,
        base_rootfs_hash,
        deployment_version,
    };
    // Past this point the FC is dead and its disk released, so a store error must not strand the
    // id in `Hibernating` (wakes would time out on it; deploys + boot_db_vm would wait it out and
    // fail): fail OPEN — no snapshot meta ⇒ the next wake cold-boots — and still settle below.
    if let Err(e) = plat.store.save_snapshot_meta(&meta) {
        tracing::error!(project = %project_id, error = %e,
            "persisting snapshot meta failed; settling Hibernated without a snapshot (cold boot next)");
        let _ = plat.store.remove_snapshot_meta(project_id);
    }

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        if let Err(e) = plat.store.update_project(&proj) {
            tracing::warn!(project = %project_id, error = %e, "persisting Hibernated project state failed");
        }
    }

    // Keep TAP device and VmAllocation for fast restore
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);
    plat.vm_incarnations.retire(project_id);

    info!(project = %project_id, "VM hibernated");
    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::db_vm::boot_db_vm;
    use crate::vm_runtime::reap_firecracker;
    use crate::{DISK_LEASE_TTL, Incarnations, rootfs_cas, teardown_tap, wake_project_inner};
    use jkbase_common::config::PlatformEgress;
    use jkbase_control::logstore::LogStore;
    use jkbase_control::store::{ProjectState, Store};
    use jkbase_proxy::DomainMap;
    use jkbase_substrate::{FlockLease, LocalLoop};
    use std::collections::HashMap;
    use std::sync::atomic::AtomicBool;

    use super::*;
    use crate::tap::run_cmd;
    use std::path::PathBuf;

    /// On-box, real Firecracker: a dedicated-DB redeploy (`boot_db_vm`) lands while the DB VM is
    /// mid-`hibernate_project` (lock dropped, paused FC still mapping the disk). Whatever order the
    /// two settle in, the result must be ONE coherent incarnation: the new DB VM `Running`, its VM
    /// handle + disk token present, that token still the live lease holder, the disk attached
    /// exactly once, exactly one FC for the id, its agent serving, and no snapshot meta that a
    /// later wake could restore over it. Pre-fix this broke: the supersede released the paused
    /// FC's token, the fence reaped it, and hibernate's cleanup then tore down the new boot.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/.firecracker JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/.firecracker/baselayers \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity-cur.ext4 \
    ///       <test-bin> --ignored --nocapture db_vm_redeploy_during_hibernate_onbox
    ///
    /// Needs the runtime bridge `jkbr0` at 172.16.0.1/24 (created + removed here if absent) and
    /// `ebtables` (the TAP source-guard). `JKB_RACE_ROUNDS` (default 3) repeats the race.
    #[tokio::test]
    #[ignore = "on-box: needs KVM + root + baselayers + verity rootfs (JKB_ROOTFS)"]
    async fn db_vm_redeploy_during_hibernate_onbox() {
        let env = |k: &str| std::env::var(k).ok().map(PathBuf::from);
        let (Some(fc_data), Some(fc_release), Some(baselayers), Some(rootfs)) = (
            env("JKB_DATA"),
            env("JKB_FC_RELEASE"),
            env("JKB_BASELAYERS"),
            env("JKB_ROOTFS"),
        ) else {
            eprintln!("skip: set JKB_DATA, JKB_FC_RELEASE, JKB_BASELAYERS, JKB_ROOTFS");
            return;
        };
        let rounds: usize = std::env::var("JKB_RACE_ROUNDS")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(3);
        let kernel = if fc_data.join("vmlinux.bin").exists() {
            fc_data.join("vmlinux.bin")
        } else {
            fc_data.join("vmlinux-6.12.92.bin")
        };

        // Runtime bridge: setup_tap enslaves every TAP to jkbr0.
        let made_bridge = !std::process::Command::new("ip")
            .args(["link", "show", "jkbr0"])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .unwrap()
            .success();
        if made_bridge {
            run_cmd("ip", &["link", "add", "name", "jkbr0", "type", "bridge"])
                .await
                .unwrap();
            run_cmd("ip", &["addr", "add", "172.16.0.1/24", "dev", "jkbr0"])
                .await
                .unwrap();
            run_cmd("ip", &["link", "set", "jkbr0", "up"])
                .await
                .unwrap();
        }

        // A fresh data dir holding just what boot_db_vm reads: the BASE project's live tree (a
        // DbOnly image needs only `_database.json` + schema) and the shared baselayers store.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let data_dir = std::env::temp_dir().join(format!("jkbase-dbrace-{nanos}"));
        let pid = "dbrace";
        let db_id = vm_identity::vm_id(pid, vm_identity::VmRole::Db);
        let live = data_dir.join("hosting").join(pid).join("live");
        std::fs::create_dir_all(live.join("_database")).unwrap();
        std::fs::write(
            live.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null,"tier":"dedicated"}"#,
        )
        .unwrap();
        std::fs::write(
            live.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();
        for d in ["content-images", "run", "snapshots", "logs"] {
            std::fs::create_dir_all(data_dir.join(d)).unwrap();
        }
        std::os::unix::fs::symlink(&baselayers, data_dir.join("baselayers")).unwrap();

        let store = Store::open(&data_dir.join("control.redb")).unwrap();
        store
            .create_project(&jkbase_control::store::Project {
                id: pid.to_string(),
                name: pid.to_string(),
                tenant_id: None,
                current_version: Some(1),
                state: ProjectState::Active,
                vm_ip: None,
                domains: Vec::new(),
            })
            .unwrap();
        // Boot from a CAS-shaped rootfs path so a hibernate's snapshot is restore-viable on wake.
        let rootfs_hash = "a".repeat(64);
        let cas_dir = data_dir.join("base-rootfs");
        std::fs::create_dir_all(&cas_dir).unwrap();
        let cas_rootfs = rootfs_cas::blob_path(&cas_dir, &rootfs_hash);
        std::os::unix::fs::symlink(&rootfs, &cas_rootfs).unwrap();
        let host_id = "dbrace-host".to_string();
        let platform = Arc::new(Mutex::new(PlatformState {
            vms: HashMap::new(),
            vm_states: HashMap::new(),
            vm_incarnations: Incarnations::default(),
            db_boots: HashMap::new(),
            vm_rootfs_hashes: HashMap::new(),
            wake_failures: HashMap::new(),
            store,
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel,
            base_rootfs_path: cas_rootfs,
            base_rootfs_hash: rootfs_hash,
            data_dir: data_dir.clone(),
            data_disk: Arc::new(LocalLoop::open(data_dir.join("data-disks")).unwrap()),
            lease: Arc::new(FlockLease::open(data_dir.join("leases"), host_id.clone()).unwrap()),
            disk_tokens: HashMap::new(),
            host_id,
            is_leader: Arc::new(AtomicBool::new(true)),
            platform_egress: PlatformEgress::default(),
        }));
        let routing: jkbase_proxy::RoutingTable = Default::default();
        let domain_map: DomainMap = Default::default();
        let logs = data_dir.join("logs");
        let shipper = LogShipper::new(LogStore::new(logs.clone()), logs.join(".cursors.json"));
        let reach = jkbase_common::config::DbReachFacts {
            splice_secret: "dbrace-splice-secret-0123456789abcdef".to_string(),
            admin_token: "jkba_dbrace-admin-token-0123456789abcdef".to_string(),
            dedicated: false,
            jwks: None,
        };

        let fc_count = || {
            let out = std::process::Command::new("pgrep")
                .args(["-f", &vm_identity::fc_sock_pkill_pattern(&db_id)])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).lines().count()
        };
        let img = data_dir.join("data-disks").join(format!("{db_id}.img"));
        let loop_count = || {
            let out = std::process::Command::new("losetup")
                .args(["-j", img.to_str().unwrap()])
                .output()
                .unwrap();
            String::from_utf8_lossy(&out.stdout).lines().count()
        };

        // Run the body, then ALWAYS clean up (FCs, loops, TAP, bridge) before reporting.
        let outcome: std::result::Result<(), String> = async {
            boot_db_vm(pid, &platform, Some(&reach))
                .await
                .map_err(|e| format!("initial boot_db_vm: {e:#}"))?;
            for round in 1..=rounds {
                // Hibernate the DB VM; redeploy as soon as hibernate has dropped the lock.
                let hib = tokio::spawn({
                    let (platform, routing, shipper) =
                        (platform.clone(), routing.clone(), shipper.clone());
                    let db_id = db_id.clone();
                    async move {
                        hibernate_project(&db_id, platform, routing, shipper, None, None).await
                    }
                });
                let deadline = std::time::Instant::now() + Duration::from_secs(5);
                loop {
                    let st = platform.lock().await.vm_states.get(&db_id).copied();
                    if st == Some(VmLifecycle::Hibernating) {
                        break;
                    }
                    if std::time::Instant::now() > deadline {
                        return Err(format!("round {round}: never saw Hibernating ({st:?})"));
                    }
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
                let redeploy = boot_db_vm(pid, &platform, Some(&reach)).await;
                let hib = hib.await.unwrap();
                eprintln!("[dbrace] round {round}: redeploy={redeploy:?} hibernate={hib:?}");
                redeploy.map_err(|e| format!("round {round}: redeploy failed: {e:#}"))?;
                // Let any straggling hibernate-side cleanup land before judging.
                tokio::time::sleep(Duration::from_millis(500)).await;

                let plat = platform.lock().await;
                let state = plat.vm_states.get(&db_id).copied();
                let has_vm = plat.vms.contains_key(&db_id);
                let token = plat.disk_tokens.get(&db_id).cloned();
                let snap = plat.store.get_snapshot_meta(&db_id).ok().flatten();
                let alloc = plat.store.get_vm_allocation(&db_id).unwrap().unwrap();
                let lease = plat.lease.clone();
                drop(plat);
                let lease_ok = match &token {
                    Some(t) => lease.renew(t, DISK_LEASE_TTL).await.is_ok(),
                    None => false,
                };
                let alive = agent_alive(&alloc.ip).await;
                let (fcs, loops) = (fc_count(), loop_count());
                eprintln!(
                    "[dbrace] round {round}: state={state:?} vm={has_vm} token={} lease_ok={lease_ok} \
                     snapshot_meta={} fcs={fcs} loops={loops} agent_alive={alive}",
                    token.is_some(),
                    snap.is_some()
                );
                if state != Some(VmLifecycle::Running)
                    || !has_vm
                    || !lease_ok
                    || snap.is_some()
                    || fcs != 1
                    || loops != 1
                    || !alive
                {
                    return Err(format!("round {round}: incoherent DB VM after the race"));
                }
            }

            // Then the DB VM must still hibernate + WAKE normally (the reach plane's path): a
            // settled hibernate leaves a snapshot, and `wake_project_inner` on the `.db` id brings
            // it back Running — on main this aborted every DB-VM wake as "deleted".
            hibernate_project(&db_id, platform.clone(), routing.clone(), shipper.clone(), None, None)
                .await
                .map_err(|e| format!("final hibernate: {e:#}"))?;
            {
                let plat = platform.lock().await;
                let st = plat.vm_states.get(&db_id).copied();
                let snap = plat.store.get_snapshot_meta(&db_id).ok().flatten();
                eprintln!("[dbrace] hibernated: state={st:?} snapshot_meta={}", snap.is_some());
                if st != Some(VmLifecycle::Hibernated) || snap.is_none() {
                    return Err("final hibernate did not settle Hibernated with a snapshot".into());
                }
            }
            for wake in 1..=2 {
                let ip = wake_project_inner(
                    &db_id,
                    platform.clone(),
                    routing.clone(),
                    domain_map.clone(),
                    shipper.clone(),
                )
                .await
                .map_err(|e| format!("DB VM wake {wake}: {e:#}"))?;
                let plat = platform.lock().await;
                let state = plat.vm_states.get(&db_id).copied();
                let has_vm = plat.vms.contains_key(&db_id);
                let token = plat.disk_tokens.get(&db_id).cloned();
                let lease = plat.lease.clone();
                drop(plat);
                let lease_ok = match &token {
                    Some(t) => lease.renew(t, DISK_LEASE_TTL).await.is_ok(),
                    None => false,
                };
                let alive = agent_alive(&ip).await;
                let (fcs, loops) = (fc_count(), loop_count());
                eprintln!(
                    "[dbrace] wake {wake}: ip={ip} state={state:?} vm={has_vm} lease_ok={lease_ok} \
                     fcs={fcs} loops={loops} agent_alive={alive}"
                );
                if state != Some(VmLifecycle::Running)
                    || !has_vm
                    || !lease_ok
                    || fcs != 1
                    || loops != 1
                    || !alive
                {
                    return Err(format!("wake {wake}: incoherent DB VM"));
                }
                if wake == 1 {
                    hibernate_project(
                        &db_id,
                        platform.clone(),
                        routing.clone(),
                        shipper.clone(),
                        None,
                        None,
                    )
                    .await
                    .map_err(|e| format!("re-hibernate: {e:#}"))?;
                }
            }
            Ok(())
        }
        .await;

        // Cleanup: stop the VM, kill any straggler FC, detach the disk, drop TAP (+ bridge).
        {
            let mut plat = platform.lock().await;
            if let Some(mut vm) = plat.vms.remove(&db_id) {
                let _ = vm.stop().await;
            }
            reap_firecracker(&db_id).await;
            if let Some(t) = plat.disk_tokens.remove(&db_id) {
                let (dd, ls) = (plat.data_disk.clone(), plat.lease.clone());
                release_data_disk(&dd, &ls, &db_id, t).await;
            }
            let _ = plat.data_disk.detach(&db_id).await;
            if let Ok(Some(a)) = plat.store.get_vm_allocation(&db_id) {
                let _ = teardown_tap(&a.tap_device).await;
            }
        }
        if made_bridge {
            let _ = run_cmd("ip", &["link", "del", "jkbr0"]).await;
        }
        let _ = std::fs::remove_dir_all(&data_dir);

        outcome.unwrap();
        println!("PASS: {rounds} round(s) of DB-VM redeploy-during-hibernate left one coherent VM");
    }
}
