//! Steps shared by every path that commits a VM to Running (deploy, wake, adoption) or reaps one:
//! the re-adoption handoff record, the fast-path route registration, and the per-project FC reaper.

use crate::{handoff, proc_starttime, vm_identity};
use jkbase_control::store::{DomainRecord, VmAllocation};
use jkbase_proxy::{DomainMap, DomainTarget};
use std::path::Path;
use tracing::warn;

/// Write the per-VM re-adoption record at commit-to-Running (deploy + wake). `fc_pid` +
/// `fc_starttime` are captured from the SAME `/proc` read so the pid is pinned to one
/// incarnation. Best-effort: if `fc_pid` is unknown (FC already exited) or the write fails, we
/// skip — the only consequence is that this VM cold-boots on the next restart (the prior
/// behavior), never a correctness hazard. See [`handoff`].
#[allow(clippy::too_many_arguments)]
pub(crate) fn write_handoff_record(
    runtime_dir: &Path,
    project_id: &str,
    fc_pid: Option<u32>,
    alloc: &VmAllocation,
    loop_dev: Option<String>,
    lease_epoch: Option<u64>,
    base_rootfs_hash: String,
    deployment_version: Option<u64>,
) {
    let Some(pid) = fc_pid else {
        warn!(project = %project_id, "no FC pid at commit; skipping re-adoption handoff");
        return;
    };
    let Some(st) = proc_starttime(pid) else {
        warn!(project = %project_id, %pid, "FC pid gone at commit; skipping re-adoption handoff");
        return;
    };
    let rec = handoff::HandoffRecord {
        schema_version: handoff::SCHEMA_VERSION,
        project_id: project_id.to_string(),
        // `project_id` here is the RENDERED vm id (bare for App, `{id}.db` for a DB VM), so the
        // role is implied by its suffix — App today, Db once the dedicated-DB boot writes its own.
        role: vm_identity::split_vm_id(project_id).1,
        fc_pid: pid,
        fc_starttime: st,
        ip: alloc.ip.clone(),
        tap: alloc.tap_device.clone(),
        mac: alloc.mac.clone(),
        loop_dev,
        lease_epoch,
        base_rootfs_hash,
        deployment_version,
    };
    if let Err(e) = handoff::write(runtime_dir, project_id, &rec) {
        warn!(project = %project_id, error = %e,
            "failed to write re-adoption handoff (VM will cold-boot on next restart)");
    }
}

/// Point all of a project's Active hosts at its VM IP (fast-path routes) and
/// ensure the shared domain map reflects them. `routes` is keyed by host-key.
pub(crate) async fn register_active_routes(
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    active_domains: &[DomainRecord],
    project_id: &str,
    ip: &str,
) {
    let mut table = routing.write().await;
    let mut map = domain_map.write().await;
    // The primary label always routes, even if its DomainRecord predates the registry.
    table.insert(project_id.to_string(), ip.to_string());
    map.entry(project_id.to_string())
        .or_insert_with(|| DomainTarget {
            project_id: project_id.to_string(),
            site: None,
            acme_delegation: None,
        });
    for d in active_domains {
        table.insert(d.host.clone(), ip.to_string());
        map.insert(d.host.clone(), d.target());
    }
}

/// Reap any Firecracker process still running for `project_id` (best-effort).
pub(crate) async fn reap_firecracker(project_id: &str) {
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
}
