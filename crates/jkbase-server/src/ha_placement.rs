//! HA fleet plane: this host's heartbeat in the HOSTS registry, peer liveness, project placement
//! and orphan reassignment, the leader's desired-vs-running reconciler, and where a deploy must run.

use crate::platform::PlatformState;
use jkbase_control::store::{HostRecord, Project, ProjectState, Store, VmAllocation};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{info, warn};

/// A host is live iff it has beaten at least once and its last heartbeat is within
/// `threshold_secs` of `now`. The single liveness predicate the heartbeat detection,
/// reconciler, and placement all share.
pub(crate) fn host_is_live(h: &HostRecord, now: u64, threshold_secs: u64) -> bool {
    h.last_heartbeat != 0 && now.saturating_sub(h.last_heartbeat) <= threshold_secs
}

/// HA P3 — hosts whose heartbeat has gone stale, excluding `self_id` (we're alive) and
/// never-beaten rows (`last_heartbeat == 0`, e.g. a peer that just registered). The leader
/// reassigns these; the heartbeat loop only DETECTS them.
pub(crate) fn dead_hosts<'a>(
    hosts: &'a [HostRecord],
    now: u64,
    threshold_secs: u64,
    self_id: &str,
) -> Vec<&'a HostRecord> {
    hosts
        .iter()
        .filter(|h| h.host_id != self_id)
        .filter(|h| h.last_heartbeat != 0)
        .filter(|h| !host_is_live(h, now, threshold_secs))
        .collect()
}

/// Current allocation count per host (the placement load). Skips unplaced (empty host_id).
pub(crate) fn current_load(allocations: &[VmAllocation]) -> HashMap<String, u32> {
    let mut load: HashMap<String, u32> = HashMap::new();
    for a in allocations {
        if !a.host_id.is_empty() {
            *load.entry(a.host_id.clone()).or_insert(0) += 1;
        }
    }
    load
}

/// HA P3 placement — the least-loaded LIVE host in `region` that still has spare capacity
/// (`capacity.max_vms == 0` means unbounded). Ties broken by host_id for determinism.
/// `None` if no live host in the region can take it (region at capacity / empty).
pub(crate) fn place_project<'a>(
    hosts: &'a [HostRecord],
    load: &HashMap<String, u32>,
    region: &str,
    now: u64,
    dead_threshold_secs: u64,
) -> Option<&'a HostRecord> {
    hosts
        .iter()
        .filter(|h| h.region == region)
        .filter(|h| host_is_live(h, now, dead_threshold_secs))
        .filter(|h| {
            h.capacity.max_vms == 0
                || load.get(&h.host_id).copied().unwrap_or(0) < h.capacity.max_vms
        })
        .min_by(|a, b| {
            let la = load.get(&a.host_id).copied().unwrap_or(0);
            let lb = load.get(&b.host_id).copied().unwrap_or(0);
            la.cmp(&lb).then_with(|| a.host_id.cmp(&b.host_id))
        })
}

/// HA P3 — assign each orphaned project to a freshly-placed live host, in the SAME region
/// as its (now-dead) prior host so it stays near its data. Spreads multiple orphans by
/// simulating load as it assigns. Returns `(project_id, new_host_id)`; an orphan with no
/// available host in its region is omitted (the caller logs — region at capacity). Pure.
pub(crate) fn reassign_plan(
    orphaned: &[String],
    hosts: &[HostRecord],
    allocations: &[VmAllocation],
    now: u64,
    dead_threshold_secs: u64,
) -> Vec<(String, String)> {
    let alloc_by_project: HashMap<&str, &VmAllocation> = allocations
        .iter()
        .map(|a| (a.project_id.as_str(), a))
        .collect();
    let mut load = current_load(allocations);
    let mut out = Vec::new();
    for pid in orphaned {
        let region = alloc_by_project
            .get(pid.as_str())
            .and_then(|a| hosts.iter().find(|h| h.host_id == a.host_id))
            .map(|h| h.region.clone())
            .unwrap_or_else(|| "default".to_string());
        if let Some(h) = place_project(hosts, &load, &region, now, dead_threshold_secs) {
            *load.entry(h.host_id.clone()).or_insert(0) += 1; // simulate the assignment
            out.push((pid.clone(), h.host_id.clone()));
        }
    }
    out
}

/// HA P3 — the cluster heartbeat. Upserts THIS host's HOSTS row with a fresh
/// `last_heartbeat` every [`HEARTBEAT_INTERVAL`] (re-registering if the row vanished), so
/// peers/the leader can tell it is alive WITHOUT a cross-host TCP probe (which can't cross
/// the per-host network islands). When this host is the leader it also scans for peers
/// whose heartbeat has gone stale and logs them — the P3 reconciler consumes those to
/// reassign their projects. Single-node: the one host beats itself and sees no dead peers.
pub(crate) async fn host_heartbeat_loop(
    store: Store,
    mut self_host: HostRecord,
    is_leader: Arc<AtomicBool>,
) {
    loop {
        self_host.last_heartbeat = jkbase_control::auth::timestamp();
        if let Err(e) = store.save_host(&self_host) {
            warn!(host_id = %self_host.host_id, error = %e, "failed to write host heartbeat");
        }
        if is_leader.load(Ordering::Relaxed)
            && let Ok(hosts) = store.list_hosts()
        {
            let now = jkbase_control::auth::timestamp();
            for h in dead_hosts(
                &hosts,
                now,
                DEAD_HOST_THRESHOLD.as_secs(),
                &self_host.host_id,
            ) {
                warn!(host_id = %h.host_id, region = %h.region,
                      stale_secs = now.saturating_sub(h.last_heartbeat),
                      "dead host detected (stale heartbeat) — pending reconcile");
            }
        }
        tokio::time::sleep(HEARTBEAT_INTERVAL).await;
    }
}

/// What the leader's reconcile tick found needs doing to converge running → desired.
#[derive(Debug, Default, PartialEq, Eq)]
pub(crate) struct ReconcilePlan {
    /// Deployed, wakeable projects whose owning host is dead or absent — they need
    /// (re)placement onto a live host. Computed by the leader; APPLIED by placement (the
    /// next P3 card). Empty on a healthy single node (allocations are unplaced/local).
    orphaned: Vec<String>,
}

/// Compare desired (deployed, wakeable projects) vs running (allocations + live hosts) and
/// return the drift the leader must act on. Pure + deterministic. A host counts as live
/// iff its heartbeat is within `dead_threshold_secs`; an allocation with an empty host_id
/// is single-node/pre-placement (local) and never orphaned.
pub(crate) fn reconcile_plan(
    projects: &[Project],
    allocations: &[VmAllocation],
    hosts: &[HostRecord],
    now: u64,
    dead_threshold_secs: u64,
) -> ReconcilePlan {
    let live: HashSet<&str> = hosts
        .iter()
        .filter(|h| host_is_live(h, now, dead_threshold_secs))
        .map(|h| h.host_id.as_str())
        .collect();
    let alloc_by_project: HashMap<&str, &VmAllocation> = allocations
        .iter()
        .map(|a| (a.project_id.as_str(), a))
        .collect();
    let mut orphaned = Vec::new();
    for p in projects {
        if p.current_version.is_none() {
            continue; // never deployed → nothing to place
        }
        if !matches!(p.state, ProjectState::Active | ProjectState::Hibernated) {
            continue; // NeedsRedeploy / Stopped are not wakeable
        }
        if let Some(alloc) = alloc_by_project.get(p.id.as_str())
            && !alloc.host_id.is_empty()
            && !live.contains(alloc.host_id.as_str())
        {
            // Owned by a host that is no longer live → needs (re)placement.
            orphaned.push(p.id.clone());
        }
    }
    orphaned.sort();
    ReconcilePlan { orphaned }
}

/// HA P3 — the continuous cluster reconciler. Only the leader reconciles cluster-wide
/// (followers no-op here and reconcile their own host via the wake/boot paths). Each tick
/// it compares desired (deployed projects) vs running (allocations + live hosts) via
/// [`reconcile_plan`] and surfaces the drift; the actual (re)placement of orphaned
/// projects onto live hosts is the next P3 card (placement + ownership + deploy
/// forwarding) — this loop is the engine that drives it. Inert on a single node (no
/// placed allocations, so nothing is ever orphaned).
pub(crate) async fn reconcile_loop(
    platform: Arc<Mutex<PlatformState>>,
    is_leader: Arc<AtomicBool>,
) {
    loop {
        tokio::time::sleep(RECONCILE_INTERVAL).await;
        if !is_leader.load(Ordering::Relaxed) {
            continue;
        }
        // Hold the platform lock for the read + reassign writes — all fast redb ops, no VM
        // work here. On a single node `orphaned` is empty, so this is lock + 3 reads + bail.
        let plat = platform.lock().await;
        let projects = plat.store.list_projects().unwrap_or_default();
        let allocs = plat.store.list_vm_allocations().unwrap_or_default();
        let hosts = plat.store.list_hosts().unwrap_or_default();
        let now = jkbase_control::auth::timestamp();
        let plan = reconcile_plan(
            &projects,
            &allocs,
            &hosts,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        );
        if plan.orphaned.is_empty() {
            continue;
        }
        // Place each orphan on a live host (least-loaded in its region) and reassign: update
        // the allocation's owner + bump placement_epoch. The new owner boots it on its next
        // wake/reconcile, acquiring the disk lease (whose epoch the old host has already
        // self-fenced from); the data disk moves via the substrate DataDiskProvider (Ceph).
        let reassignments = reassign_plan(
            &plan.orphaned,
            &hosts,
            &allocs,
            now,
            DEAD_HOST_THRESHOLD.as_secs(),
        );
        for (pid, new_host) in &reassignments {
            match plat.store.get_vm_allocation(pid) {
                Ok(Some(mut alloc)) => {
                    let from = alloc.host_id.clone();
                    alloc.host_id = new_host.clone();
                    alloc.placement_epoch = alloc.placement_epoch.saturating_add(1);
                    if let Err(e) = plat.store.save_vm_allocation(&alloc) {
                        warn!(project = %pid, error = %e, "reconcile: failed to persist reassignment");
                    } else {
                        info!(project = %pid, from = %from, to = %new_host,
                              epoch = alloc.placement_epoch, "reconcile: reassigned to a live host");
                    }
                }
                _ => warn!(project = %pid, "reconcile: orphan has no allocation to reassign"),
            }
        }
        let unplaced = plan.orphaned.len() - reassignments.len();
        if unplaced > 0 {
            warn!(
                unplaced,
                "reconcile: orphaned projects with no live host in-region (cluster at capacity)"
            );
        }
    }
}

/// HA P3 — where a deploy for a project must run, given its allocation + the fleet.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum DeployTarget {
    /// Run here: we own it, or it is unplaced (single-node / pre-placement / first deploy).
    Local,
    /// Owned by a live remote host — forward the deploy there.
    Remote {
        host_id: String,
        addr: Option<String>,
    },
    /// Owned by a host that is no longer live; the reconciler must reassign it first. Fail
    /// closed (deploy is retryable) rather than have a non-owner boot a second copy.
    OwnerDead { host_id: String },
}

/// Decide where `alloc`'s deploy belongs. Local when unplaced / owned-by-me / no-alloc;
/// Remote when a live peer owns it; OwnerDead when the owner is gone. Pure.
pub(crate) fn deploy_target(
    alloc: Option<&VmAllocation>,
    hosts: &[HostRecord],
    me: &str,
    now: u64,
    dead_threshold_secs: u64,
) -> DeployTarget {
    match alloc {
        None => DeployTarget::Local,
        Some(a) if a.host_id.is_empty() || a.host_id == me => DeployTarget::Local,
        Some(a) => match hosts.iter().find(|h| h.host_id == a.host_id) {
            Some(h) if host_is_live(h, now, dead_threshold_secs) => DeployTarget::Remote {
                host_id: h.host_id.clone(),
                addr: h.public_addr.clone(),
            },
            _ => DeployTarget::OwnerDead {
                host_id: a.host_id.clone(),
            },
        },
    }
}

/// How often a host re-asserts its own liveness into HOSTS (the cluster heartbeat).
pub(crate) const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(5);

/// Past this with no heartbeat, the leader treats a host as dead and (P3 reconciler/
/// placement) reassigns its projects. Tunable for the RTO budget; kept above a few
/// heartbeat intervals so one missed beat / a brief GC pause is not a false positive.
pub(crate) const DEAD_HOST_THRESHOLD: Duration = Duration::from_secs(15);

/// How often the leader runs the continuous cluster reconcile (desired vs running).
pub(crate) const RECONCILE_INTERVAL: Duration = Duration::from_secs(10);

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_control::store::{HostCapacity, HostRecord, Project, ProjectState, VmAllocation};

    fn test_host(id: &str, region: &str, hb: u64, max_vms: u32) -> HostRecord {
        HostRecord {
            host_id: id.into(),
            region: region.into(),
            public_addr: Some(format!("{id}:9090")),
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity {
                vcpus: 0,
                mem_mib: 0,
                max_vms,
            },
        }
    }

    fn test_alloc(pid: &str, host: &str) -> VmAllocation {
        VmAllocation {
            project_id: pid.into(),
            ip: "172.16.0.2".into(),
            tap_device: "tap".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        }
    }

    #[test]
    fn place_project_picks_least_loaded_live_in_region_with_capacity() {
        let now = 1000;
        let hosts = vec![
            test_host("a", "east", 995, 0),    // live, region east, unbounded
            test_host("b", "east", 995, 0),    // live, region east
            test_host("c", "west", 995, 0),    // live, wrong region
            test_host("d", "east", 900, 0),    // east but DEAD (100s stale)
            test_host("full", "east", 995, 1), // east, live, but at capacity (1)
        ];
        // a has 2 allocations, b has 0, full has 1 (at its cap).
        let allocs = vec![
            test_alloc("p1", "a"),
            test_alloc("p2", "a"),
            test_alloc("p3", "full"),
        ];
        let load = current_load(&allocs);
        let pick = place_project(&hosts, &load, "east", now, 15).unwrap();
        assert_eq!(
            pick.host_id, "b",
            "least-loaded live in-region with capacity"
        );
        // No host in an empty region.
        assert!(place_project(&hosts, &load, "north", now, 15).is_none());
    }

    #[test]
    fn reassign_plan_spreads_orphans_across_live_in_region() {
        let now = 1000;
        let hosts = vec![
            test_host("dead", "east", 900, 0), // dead owner of the orphans
            test_host("a", "east", 995, 0),
            test_host("b", "east", 995, 0),
        ];
        // Two orphans, both previously on the dead east host → spread across a and b.
        let allocs = vec![test_alloc("p1", "dead"), test_alloc("p2", "dead")];
        let orphaned = vec!["p1".to_string(), "p2".to_string()];
        let plan = reassign_plan(&orphaned, &hosts, &allocs, now, 15);
        let targets: HashSet<&str> = plan.iter().map(|(_, h)| h.as_str()).collect();
        assert_eq!(plan.len(), 2);
        assert_eq!(
            targets,
            HashSet::from(["a", "b"]),
            "spread, not piled onto one host"
        );
    }

    #[test]
    fn deploy_target_routes_by_ownership() {
        let now = 1000;
        let hosts = vec![
            test_host("me", "east", 995, 0),
            test_host("peer", "east", 995, 0),
        ];
        // No allocation (first deploy) → local.
        assert_eq!(
            deploy_target(None, &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Unplaced (empty host_id) → local.
        assert_eq!(
            deploy_target(Some(&test_alloc("p", "")), &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Owned by me → local.
        assert_eq!(
            deploy_target(Some(&test_alloc("p", "me")), &hosts, "me", now, 15),
            DeployTarget::Local
        );
        // Owned by a live peer → forward.
        assert!(matches!(
            deploy_target(Some(&test_alloc("p", "peer")), &hosts, "me", now, 15),
            DeployTarget::Remote { ref host_id, .. } if host_id == "peer"
        ));
        // Owned by a host that is gone (not in HOSTS / dead) → fail closed.
        assert!(matches!(
            deploy_target(Some(&test_alloc("p", "ghost")), &hosts, "me", now, 15),
            DeployTarget::OwnerDead { ref host_id } if host_id == "ghost"
        ));
    }

    #[test]
    fn reconcile_plan_orphans_only_projects_on_dead_hosts() {
        // HA P3: the leader's desired-vs-running drift. A deployed, wakeable project is
        // orphaned iff its owning host is no longer live; unplaced (empty host_id),
        // live-owned, never-deployed, and non-wakeable projects are left alone.
        let proj = |id: &str, ver: Option<u64>, state: ProjectState| Project {
            id: id.into(),
            name: id.into(),
            tenant_id: Some("t".into()),
            current_version: ver,
            state,
            vm_ip: None,
            domains: vec![],
        };
        let alloc = |pid: &str, host: &str| VmAllocation {
            project_id: pid.into(),
            ip: "172.16.0.2".into(),
            tap_device: "tap".into(),
            mac: "AA".into(),
            host_id: host.into(),
            placement_epoch: 1,
        };
        let host = |id: &str, hb: u64| HostRecord {
            host_id: id.into(),
            region: "r".into(),
            public_addr: None,
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity::default(),
        };
        let now = 1000;
        let projects = vec![
            proj("on-dead", Some(1), ProjectState::Hibernated), // owner dead → orphan
            proj("on-live", Some(1), ProjectState::Active),     // owner live → ok
            proj("unplaced", Some(1), ProjectState::Hibernated), // empty host_id → ok
            proj("undeployed", None, ProjectState::Active),     // no version → ignored
            proj("needs", Some(1), ProjectState::NeedsRedeploy), // not wakeable → ignored
        ];
        let allocs = vec![
            alloc("on-dead", "host-dead"),
            alloc("on-live", "host-live"),
            alloc("unplaced", ""),
            alloc("needs", "host-dead"),
        ];
        let hosts = vec![host("host-live", 995), host("host-dead", 970)]; // dead = 30s stale
        let plan = reconcile_plan(&projects, &allocs, &hosts, now, 15);
        assert_eq!(plan.orphaned, vec!["on-dead".to_string()]);
    }

    #[test]
    fn dead_hosts_flags_only_stale_peers() {
        // HA P3: the leader treats a peer as dead only when its heartbeat is genuinely
        // stale — never itself, and never a just-registered peer that hasn't beat yet.
        let h = |id: &str, hb: u64| HostRecord {
            host_id: id.into(),
            region: "r".into(),
            public_addr: None,
            last_heartbeat: hb,
            cpu_template_id: None,
            kernel_id: None,
            capacity: HostCapacity::default(),
        };
        let now = 1000;
        let hosts = vec![
            h("self", 999),  // me — excluded even though "fresh"
            h("fresh", 990), // 10s ago, within threshold → alive
            h("stale", 980), // 20s ago, past 15s → dead
            h("never", 0),   // registered, never beat → excluded (not a false positive)
        ];
        let dead: Vec<&str> = dead_hosts(&hosts, now, 15, "self")
            .iter()
            .map(|h| h.host_id.as_str())
            .collect();
        assert_eq!(dead, vec!["stale"]);
    }
}
