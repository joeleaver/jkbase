//! VM re-adoption (zero-bounce §6b): on boot, verify every runtime Firecracker that survived the
//! previous process, re-adopt the live ones (fresh disk fence, no detach, rebuilt routing) and reap
//! the rest. A survivor is trusted only when its pid, start time and API-socket peer all agree.

use crate::agent_client::{agent_alive, agent_protocol_version};
use crate::ha_lease::DISK_LEASE_TTL;
use crate::platform::{PlatformState, RUNTIME_CGROUP_PARENT, VmLifecycle};
use crate::vm_runtime::register_active_routes;
use crate::{handoff, rootfs_cas, vm_identity};
use jkbase_orch::vm::VmInstance;
use jkbase_proxy::DomainMap;
use jkbase_substrate::{DataDiskProvider, Lease, SubstrateError};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// Process start time (jiffies since boot) from field 22 of `/proc/<pid>/stat`, or `None` if
/// gone/unparseable. (Mirrors the substrate/orch helpers; main can't reach those privates.)
pub(crate) fn proc_starttime(pid: u32) -> Option<u64> {
    let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).ok()?;
    let after = stat.rsplit_once(')')?.1;
    after.split_whitespace().nth(19)?.parse().ok()
}

/// True iff `pid` is alive AND still the same incarnation as `starttime` (PID-reuse-proof).
pub(crate) fn proc_alive_at(pid: u32, starttime: u64) -> bool {
    matches!(proc_starttime(pid), Some(st) if st == starttime)
}

/// Peer pid listening on a Firecracker api-sock, via `SO_PEERCRED`. Binds the socket-liveness
/// probe to a SPECIFIC pid at re-adoption time: the survivor's api-sock must be answered by
/// exactly `fc_pid` — not an unrelated process that bound the path, nor a recycled pid. `None`
/// if the socket is absent/unconnectable or the credential read fails (fail-closed).
pub(crate) fn socket_peer_pid(socket_path: &Path) -> Option<u32> {
    use std::os::fd::AsRawFd;
    use std::os::unix::net::UnixStream;
    let stream = UnixStream::connect(socket_path).ok()?;
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: cred/len are sized to ucred; getsockopt writes at most `len` bytes into cred.
    let rc = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut cred as *mut libc::ucred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0 || cred.pid <= 0 {
        return None;
    }
    Some(cred.pid as u32)
}

/// SIGKILL a non-survivor runtime Firecracker by exact pid and confirm its death (bounded).
/// The holder record is deliberately LEFT in place so a later cold-boot's `attach_rwo` runs
/// its fail-CLOSED preempt; deleting it would make `attach_rwo` fail-OPEN. The caller removes
/// only `handoff.json`.
///
/// TOCTOU-guarded: only kills if `fc_pid` is STILL the firecracker serving `expected_sock` — the
/// FC could have exited during the seconds of verification between enumeration and here, and its
/// pid been recycled to an unrelated process; a bare-pid SIGKILL would then hit a bystander.
pub(crate) async fn reap_runtime_fc(fc_pid: u32, expected_sock: &Path) {
    let sock_bytes = expected_sock.to_string_lossy().into_owned().into_bytes();
    let still_ours = std::fs::read(format!("/proc/{fc_pid}/cmdline"))
        .map(|raw| {
            raw.split(|b| *b == 0)
                .any(|arg| arg == sock_bytes.as_slice())
        })
        .unwrap_or(false);
    if !still_ours {
        warn!(%fc_pid, sock = %expected_sock.display(),
            "VM re-adoption: pid is no longer the FC for this api-sock (exited/recycled); not killing");
        return;
    }
    warn!(%fc_pid, "VM re-adoption: reaping non-survivor runtime Firecracker");
    let _ = std::process::Command::new("kill")
        .arg("-KILL")
        .arg(fc_pid.to_string())
        .status();
    // Confirm death so a slow exit can't still be mapping a data loop when a cold-boot reopens
    // it. /proc-existence is enough here (a fresh-killed pid won't be recycled in this window).
    for _ in 0..60 {
        if !Path::new(&format!("/proc/{fc_pid}")).exists() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    warn!(%fc_pid, "reaped runtime FC did not exit within 3s");
}

/// Outcome of evaluating one surviving runtime Firecracker.
pub(crate) enum AdoptOutcome {
    Adopted,
    Reaped,
    /// A second live `jkbase-server` legitimately holds the disk (`LeaseHeld`) — we refuse this
    /// project and leave the survivor UNTOUCHED (never kill a live peer's VM). Single-host: a
    /// misconfiguration for an operator to resolve; we don't abort the whole startup over it.
    SkippedPeerOwned,
}

/// VM re-adoption (§4/§5/§6b): verify every runtime Firecracker that SURVIVED the prior
/// `jkbase-server`, re-adopt the live ones (re-acquire the lease at a fresh epoch, re-fence the
/// disk WITHOUT detaching, rebuild `vms`/`vm_states`/`routing`) and reap the rest. Runs ONCE at
/// startup, AFTER `PlatformState` is built and BEFORE the proxy binds or any wake-capable loop
/// (scheduler/idle/wake) runs. Replaces the old blunt `pkill -9 firecracker` boot reaper.
pub(crate) async fn adopt_or_reap_runtime_vms(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
) {
    let (runtime_dir, data_disk, lease, host_id) = {
        let plat = platform.lock().await;
        (
            plat.data_dir.join("run"),
            plat.data_disk.clone(),
            plat.lease.clone(),
            plat.host_id.clone(),
        )
    };
    let fcs = rootfs_cas::list_runtime_firecrackers(&runtime_dir);
    if fcs.is_empty() {
        return;
    }
    info!(
        count = fcs.len(),
        "VM re-adoption: examining surviving runtime Firecrackers"
    );
    let (mut adopted, mut reaped, mut skipped) = (0usize, 0usize, 0usize);
    for (fc_pid, sock) in fcs {
        let Some(id) = sock
            .parent()
            .and_then(|p| p.file_name())
            .map(|s| s.to_string_lossy().into_owned())
        else {
            warn!(%fc_pid, sock = %sock.display(), "re-adoption: cannot derive project id; reaping");
            reap_runtime_fc(fc_pid, &sock).await;
            reaped += 1;
            continue;
        };
        match adopt_one_survivor(
            platform,
            routing,
            domain_map,
            &runtime_dir,
            &data_disk,
            &lease,
            &host_id,
            &id,
            fc_pid,
            &sock,
        )
        .await
        {
            AdoptOutcome::Adopted => adopted += 1,
            AdoptOutcome::Reaped => reaped += 1,
            AdoptOutcome::SkippedPeerOwned => skipped += 1,
        }
    }
    info!(adopted, reaped, skipped, "VM re-adoption complete");
}

/// Evaluate + (re-)adopt or reap a single surviving runtime Firecracker `fc_pid` for `id`.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn adopt_one_survivor(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    runtime_dir: &Path,
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    id: &str,
    fc_pid: u32,
    sock: &Path,
) -> AdoptOutcome {
    // (1) Strict handoff. No valid record ⇒ a true orphan (crash between spawn and
    // handoff-write) ⇒ reap; delete only handoff.json (NOT the holder — leave the
    // fail-closed preempt for a later attach_rwo).
    let Some(rec) = handoff::read_strict(runtime_dir, id) else {
        warn!(project = %id, %fc_pid, "re-adoption: no valid handoff (orphan); reaping");
        reap_runtime_fc(fc_pid, sock).await;
        handoff::remove(runtime_dir, id);
        return AdoptOutcome::Reaped;
    };

    // (2) Verify SURVIVOR. Each check is fail-closed → reap on any miss.
    let reap = |why: &'static str| {
        warn!(project = %id, %fc_pid, reason = why, "re-adoption: not a survivor; reaping + cold-boot on next request");
    };
    if rec.fc_pid != fc_pid {
        reap("handoff pid mismatch");
    } else if !proc_alive_at(fc_pid, rec.fc_starttime) {
        reap("pid not alive at recorded start time");
    } else if socket_peer_pid(sock) != Some(fc_pid) {
        reap("api-sock SO_PEERCRED peer != fc_pid");
    } else if !agent_alive(&rec.ip).await {
        // The AGENT HTTP layer — NOT the bare FC api-sock, which a *paused* FC still answers
        // (the paused-FC-resurrection hole). A real survivor has a live, serving guest.
        reap("agent HTTP layer not answering");
    } else if matches!(agent_protocol_version(&rec.ip).await, Some(v) if v != jkbase_common::AGENT_PROTOCOL_VERSION)
    {
        // Agent-protocol skew: force-recycle (reap → cold-boot on the NEW agent) rather than
        // keep talking the old wire format. Absent header ⇒ compatible (pre-versioning agent).
        reap("agent protocol version skew");
    } else {
        // All checks passed — proceed to adopt below.
        return finish_adoption(
            platform,
            routing,
            domain_map,
            runtime_dir,
            data_disk,
            lease,
            host_id,
            id,
            fc_pid,
            rec,
        )
        .await;
    }
    // Any verification miss fell through to here.
    reap_runtime_fc(fc_pid, sock).await;
    handoff::remove(runtime_dir, id);
    AdoptOutcome::Reaped
}

/// Re-fence + commit a VERIFIED survivor. Split out so the verification arm stays readable.
#[allow(clippy::too_many_arguments)]
pub(crate) async fn finish_adoption(
    platform: &Arc<Mutex<PlatformState>>,
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    runtime_dir: &Path,
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    id: &str,
    fc_pid: u32,
    rec: handoff::HandoffRecord,
) -> AdoptOutcome {
    let sock = runtime_dir.join(id).join("firecracker.sock");
    // (3) Re-fence the data disk WITHOUT detaching — only for projects that have one. The old
    // process's flock released on its exit, so acquire wins at a fresh (higher) epoch.
    let token = if let Some(loop_dev) = rec.loop_dev.clone() {
        let token = match lease.acquire(id, host_id, DISK_LEASE_TTL).await {
            Ok(t) => t,
            Err(SubstrateError::LeaseHeld { .. }) => {
                // §5.1: a second live server owns the disk. Do NOT adopt and do NOT kill the
                // survivor — refuse this project loudly and move on (never one instance "fixing"
                // a misconfig by SIGKILLing the other's tenant VM).
                tracing::error!(project = %id,
                    "re-adoption: data-disk lease is HELD by another live jkbase-server — refusing \
                     this project and leaving its VM untouched (resolve the duplicate server)");
                return AdoptOutcome::SkippedPeerOwned;
            }
            Err(e) => {
                tracing::warn!(project = %id, error = %e, "re-adoption: lease acquire failed; reaping");
                reap_runtime_fc(fc_pid, &sock).await;
                handoff::remove(runtime_dir, id);
                return AdoptOutcome::Reaped;
            }
        };
        // adopt_writer re-pins the holder at the fresh epoch + verified writer, fail-closed
        // (fresh kernel loop-backing read + fc_pid fd proof + starttime pin). On ANY doubt,
        // RELEASE the freshly-acquired lease FIRST (else the cold-boot's own acquire would hit
        // LeaseHeld against this very process — the §5.3 self-deadlock), then reap → cold-boot.
        if let Err(e) = data_disk
            .adopt_writer(id, &token, &loop_dev, fc_pid, rec.fc_starttime)
            .await
        {
            tracing::warn!(project = %id, error = %e,
                "re-adoption: adopt_writer failed; releasing lease + reaping for cold boot");
            let _ = lease.release(&token).await;
            reap_runtime_fc(fc_pid, &sock).await;
            handoff::remove(runtime_dir, id);
            return AdoptOutcome::Reaped;
        }
        Some(token)
    } else {
        None // diskless project: no lease, no disk_tokens entry (mirrors the deploy/wake path)
    };

    // (4) Commit under the platform lock. Re-validate the project still exists (a delete could
    // have landed via the control API). If gone: kill the FC + release/detach AWAITED, reap.
    let vm = VmInstance::adopt(
        id,
        runtime_dir,
        fc_pid,
        rec.fc_starttime,
        Some(Path::new(RUNTIME_CGROUP_PARENT)),
    );
    let over_quota;
    let active_domains;
    {
        let mut plat = platform.lock().await;
        // A survivor's rendered id may be a DB VM (`{base}.db`): resolve its BASE project for every
        // store/quota/domain read (the DB VM has no project row of its own). Per-VM state (maps,
        // lease, disk) stays keyed by the rendered `id`.
        let (base_pid, vm_role) = vm_identity::split_vm_id(id);
        if plat.store.get_project(base_pid).ok().flatten().is_none() {
            drop(plat);
            let mut vm = vm;
            let _ = vm.stop().await; // synchronous-to-death before detaching the disk
            if let Some(token) = token {
                let _ = data_disk.detach(id).await;
                let _ = lease.release(&token).await;
            }
            handoff::remove(runtime_dir, id);
            warn!(project = %id, "re-adoption: project was deleted; reaped");
            return AdoptOutcome::Reaped;
        }
        over_quota = plat
            .store
            .get_quota_status(base_pid)
            .ok()
            .flatten()
            .map(|s| s.bandwidth_blocked)
            .unwrap_or(false);
        if let Some(token) = &token {
            plat.disk_tokens.insert(id.to_string(), token.clone());
        }
        plat.vms.insert(id.to_string(), vm);
        plat.vm_states.insert(id.to_string(), VmLifecycle::Running);
        plat.vm_incarnations.commit(id);
        plat.vm_rootfs_hashes
            .insert(id.to_string(), rec.base_rootfs_hash.clone());
        plat.wake_failures.remove(id);
        // A DB VM is reached host-mediated and never proxy-routed → no domains to register.
        active_domains = if vm_role == vm_identity::VmRole::Db {
            Vec::new()
        } else {
            plat.store
                .list_active_domains_for_project(base_pid)
                .unwrap_or_default()
        };
    }

    // Rewrite the handoff with the refreshed lease epoch so run/<id>/handoff.json stays
    // consistent with disk_tokens (pid/starttime/loop_dev unchanged — same FC, same loop).
    let mut rec2 = rec;
    rec2.lease_epoch = token.as_ref().map(|t| t.epoch);
    let _ = handoff::write(runtime_dir, id, &rec2);

    // (5) Route — UNLESS this is the DB VM (never proxy-routed; reached host-mediated) or the
    // project is over quota (§10): then leave it unrouted so it isn't served; the idle loop
    // hibernates it and a request is refused by wake_project's quota gate.
    if vm_identity::split_vm_id(id).1 == vm_identity::VmRole::Db {
        info!(project = %id, "re-adoption: DB VM survivor (host-mediated; not registering routes)");
    } else if over_quota {
        warn!(project = %id, "re-adoption: adopted an OVER-QUOTA survivor; not registering routes");
    } else {
        register_active_routes(routing, domain_map, &active_domains, id, &rec2.ip).await;
    }
    info!(project = %id, %fc_pid, ip = %rec2.ip, "VM re-adopted (no bounce)");
    AdoptOutcome::Adopted
}
