//! The metering + quota-enforcement loop: samples per-project CPU, bandwidth and storage into
//! hourly rollup buckets (host-side reads only, see [`crate::metering`]) and hibernates + blocks
//! projects that exceed their monthly caps.

use crate::hibernate::hibernate_project;
use crate::log_shipper::LogShipper;
use crate::platform::{PlatformState, VmLifecycle};
use crate::project_facts::db_reach_target_vm;
use crate::{metering, vm_identity};
use jkbase_control::store::{QuotaStatus, month_start_epoch};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;

/// Sample interval. Coarse — usage is billed over hours, not seconds.
pub(crate) const METERING_TICK: Duration = Duration::from_secs(60);

/// Keep ~3 months of hourly buckets; prune older so month-to-date is never lost.
pub(crate) const USAGE_RETENTION_SECS: u64 = 90 * 86400;

/// Host-side metering + quota enforcement. Each tick: sample per-project CPU
/// (/proc), bandwidth (TAP /sys, delta-accumulated), and storage (on-disk), roll
/// them into the current hour bucket, then enforce the monthly bandwidth cap by
/// hibernating + flagging over-quota projects (the wake gate refuses to wake a
/// flagged project). All `/proc`,`/sys`,fs I/O happens with the platform lock
/// released (the log_shipper_loop idiom).
pub(crate) async fn metering_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    db_registry: Option<Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
    // The L4 plane's drop/event counters are drained + logged here (observability §8), and its
    // reflection kill-switch is enforced: a flow flagged reflection-suspected (sustained
    // egress:ingress above `amp_k`, or a destination-entropy spike) force-hibernates its VM.
    l4_plane: Option<Arc<jkbase_proxy::l4_plane::L4Plane>>,
) {
    let mut state = metering::SamplerState::default();
    let mut last_sample = Instant::now();
    let mut ticks: u64 = 0;

    loop {
        tokio::time::sleep(METERING_TICK).await;
        ticks += 1;

        // L4 observability + kill-switch (independent of the per-project rollups below). Drain the
        // per-reason drop/event counters and emit a sampled structured log so an operator can SEE a
        // spoof flood or reflection attempt in flight. Then force-hibernate any base project the
        // plane flagged reflection-suspected (design §8 automatic egress kill-switch): closing the
        // guest stops the reflected replies at the source, and the plane's own signature clears on
        // cooldown so it can wake again cleanly.
        if let Some(plane) = &l4_plane {
            let c = plane.drain_counters();
            if c.rate_cap
                | c.budget_full
                | c.warm_full_global
                | c.flow_full_project
                | c.flow_full_global
                | c.header_auth_fail
                | c.nonce_replay
                | c.stale_epoch
                | c.unknown_flow
                | c.egress_amp_clamp
                | c.egress_per_source
                | c.egress_per_victim
                | c.egress_per_project
                | c.egress_per_24
                | c.egress_global
                | c.c0_grant_rejected
                | c.wakes_admitted
                | c.promotions
                | c.reflection_shape_flagged
                != 0
            {
                info!(
                    target: "l4_metrics",
                    rate_cap = c.rate_cap, budget_full = c.budget_full, warm_full_global = c.warm_full_global,
                    flow_full_project = c.flow_full_project, flow_full_global = c.flow_full_global,
                    header_auth_fail = c.header_auth_fail, nonce_replay = c.nonce_replay, stale_epoch = c.stale_epoch,
                    // unknown_flow = an authenticated return frame for a flow_id the host no
                    // longer holds: the agent is pumping a tuple whose return leg is dead.
                    unknown_flow = c.unknown_flow,
                    egress_amp_clamp = c.egress_amp_clamp,
                    // egress_per_source = the TENANT's own per-(port,destination) cap refused it.
                    // egress_per_victim = the PLATFORM third-party backstop refused it. These are
                    // different questions and must never be read as one number: the second is the
                    // reflection bound, and a tick reporting only it used to emit no line at all.
                    egress_per_source = c.egress_per_source, egress_per_victim = c.egress_per_victim,
                    egress_per_project = c.egress_per_project, egress_per_24 = c.egress_per_24, egress_global = c.egress_global,
                    c0_grant_rejected = c.c0_grant_rejected, c0_grants = c.c0_grants,
                    wakes_admitted = c.wakes_admitted, wakes_coalesced = c.wakes_coalesced,
                    promotions = c.promotions, provisional_expired = c.provisional_expired,
                    reflection_shape_flagged = c.reflection_shape_flagged,
                    "l4 plane counters (tick)"
                );
            }
            // Iterate the SUSPECTED set directly: warm_projects() is the billing view and
            // deliberately EXCLUDES reflection-suspected bases (§6 unbilled-suspected-hours), so
            // iterating it here would never see a suspected project (the kill-switch would be dead
            // code). reflection_suspected_projects() returns exactly the set to force-hibernate.
            for base in plane.reflection_suspected_projects() {
                let is_running =
                    { platform.lock().await.vm_states.get(&base) == Some(&VmLifecycle::Running) };
                if is_running {
                    tracing::warn!(project = %base, "l4 reflection kill-switch: force-hibernating high-ratio/high-entropy flows");
                    if let Err(e) = hibernate_project(
                        &base,
                        platform.clone(),
                        routing.clone(),
                        shipper.clone(),
                        None,
                        None,
                    )
                    .await
                    {
                        tracing::error!(project = %base, error = %e, "l4 kill-switch hibernate failed");
                    }
                }
            }
        }
        let now = jkbase_control::auth::timestamp();
        let hour_epoch = now / 3600 * 3600;
        let elapsed = last_sample.elapsed().as_secs().max(1);
        last_sample = Instant::now();

        // Snapshot everything we need under one platform lock, then release it
        // before any /proc, /sys, or filesystem I/O.
        let (running_pids, allocs, projects, data_dir, store) = {
            let plat = platform.lock().await;
            let running_pids: Vec<(String, u32)> = plat
                .vm_states
                .iter()
                .filter(|(_, s)| **s == VmLifecycle::Running)
                .filter_map(|(id, _)| {
                    plat.vms
                        .get(id)
                        .and_then(|vm| vm.pid())
                        .map(|pid| (id.clone(), pid))
                })
                .collect();
            let allocs: Vec<(String, String)> = plat
                .store
                .list_vm_allocations()
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.project_id, a.tap_device))
                .collect();
            let projects: Vec<String> = plat
                .store
                .list_projects()
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.id)
                .collect();
            (
                running_pids,
                allocs,
                projects,
                plat.data_dir.clone(),
                plat.store.clone(),
            )
        };

        // CPU deltas (only Running VMs have a live pid).
        let mut cpu: HashMap<String, u64> = HashMap::new();
        for (id, pid) in &running_pids {
            if let Some(cur) = metering::read_cpu_jiffies(*pid) {
                cpu.insert(id.clone(), state.cpu_delta(id, *pid, cur));
            }
        }
        // Bandwidth deltas from each project's TAP.
        let mut bw: HashMap<String, (u64, u64)> = HashMap::new();
        for (id, tap) in &allocs {
            if let Some((rx, tx)) = metering::read_tap_bytes(tap) {
                bw.insert(id.clone(), state.tap_delta(id, tap, rx, tx));
            }
        }

        // A dedicated project's DB VM has its OWN alloc row (`{id}.db`) but no project row, so the
        // per-project roll below skips it — accrue its usage under the rendered id (decision #3:
        // separate rows, rolled up in display by `get_project_usage`). cpu/bw are already keyed by
        // the rendered id. Storage is NOT: its `{id}.db.img` disk + `{id}.db.ext4` image are billed
        // on the BASE row by `project_storage_bytes`, the same figure the deploy + object-store
        // caps enforce — sampling them here too would double-bill.
        let db_vm_ids: Vec<String> = allocs
            .iter()
            .map(|(id, _)| id.clone())
            .filter(|id| vm_identity::split_vm_id(id).1 == vm_identity::VmRole::Db)
            .collect();

        // Roll each VM's sample into its current hour bucket. Skip VMs with nothing to record (no
        // storage, no deltas) to avoid empty rows.
        let roll = |id: &str, bills_storage: bool| {
            let cpu_j = cpu.get(id).copied().unwrap_or(0);
            let (rx, tx) = bw.get(id).copied().unwrap_or((0, 0));
            let storage = if bills_storage {
                jkbase_common::storage::project_storage_bytes(&data_dir, id)
            } else {
                0
            };
            if cpu_j == 0 && rx == 0 && tx == 0 && storage == 0 {
                return;
            }
            if let Err(e) = store.add_usage(id, hour_epoch, cpu_j, rx, tx, storage, elapsed) {
                tracing::warn!(project = %id, error = %e, "metering: add_usage failed");
            }
        };
        for id in &projects {
            roll(id, true);
        }
        for id in &db_vm_ids {
            roll(id, false);
        }

        // DB-attributable warm-seconds: accrue for the VM a managed-DB reach-plane relay is holding
        // warm (`conn_count > 0`). This is the resource an idle external DB connection consumes — the
        // VM would otherwise hibernate — so it's metered (billable), complementing the per-tenant
        // warm-VM cap enforced at relay registration. Relays are keyed by the BASE project, and the
        // warm VM is the reach TARGET (the DB VM when dedicated, else the app VM) — attribute only to
        // it, never both, so a dedicated project isn't double-billed. The in-VM app->DB path never
        // registers a relay, so it's not double-counted here.
        if let Some(reg) = &db_registry {
            for (id, _pid) in &running_pids {
                let base = vm_identity::base_project_id(id);
                if reg.conn_count(base) > 0
                    && id == &db_reach_target_vm(&data_dir, base)
                    && let Err(e) = store.add_warm_usage(id, hour_epoch, elapsed)
                {
                    tracing::warn!(project = %id, error = %e, "metering: add_warm_usage failed");
                }
            }
        }

        // --- Quota enforcement (monthly bandwidth cap) ---
        let month_start = month_start_epoch(now);
        for id in &projects {
            let cap = store
                .get_quota(id)
                .map(|q| q.bandwidth_bytes_per_month)
                .unwrap_or(u64::MAX);
            let mtd = store.sum_month_to_date(id, month_start).unwrap_or_default();
            let used = mtd.rx_bytes.saturating_add(mtd.tx_bytes);
            let status = store.get_quota_status(id).ok().flatten();
            let blocked = status
                .as_ref()
                .map(|s| s.bandwidth_blocked)
                .unwrap_or(false);

            if used > cap && !blocked {
                // Write the block FIRST (source of truth for the wake gate) so a
                // request racing the hibernate is refused, then hibernate.
                let _ = store.save_quota_status(&QuotaStatus {
                    project_id: id.clone(),
                    bandwidth_blocked: true,
                    blocked_reason: Some("monthly bandwidth cap exceeded".to_string()),
                    blocked_at: now,
                    blocked_month: month_start,
                });
                tracing::warn!(project = %id, used, cap, "bandwidth cap exceeded; hibernating + blocking wake");
                let is_running =
                    { platform.lock().await.vm_states.get(id) == Some(&VmLifecycle::Running) };
                if is_running
                    && let Err(e) = hibernate_project(
                        id,
                        platform.clone(),
                        routing.clone(),
                        shipper.clone(),
                        None,
                        None,
                    )
                    .await
                {
                    tracing::error!(project = %id, error = %e, "failed to hibernate over-quota project");
                }
            } else if blocked {
                // Clear on month rollover (new period) or if usage is back under
                // cap (e.g. an admin raised the override).
                let stale_month = status
                    .as_ref()
                    .map(|s| s.blocked_month != month_start)
                    .unwrap_or(false);
                if stale_month || used <= cap {
                    let _ = store.save_quota_status(&QuotaStatus {
                        project_id: id.clone(),
                        bandwidth_blocked: false,
                        blocked_reason: None,
                        blocked_at: 0,
                        blocked_month: month_start,
                    });
                    tracing::info!(project = %id, "bandwidth block cleared");
                }
            }
        }

        // Prune old buckets roughly hourly (60 ticks * 60s).
        if ticks.is_multiple_of(60) {
            let cutoff_hour = now.saturating_sub(USAGE_RETENTION_SECS) / 3600 * 3600;
            if let Ok(n) = store.prune_usage(cutoff_hour)
                && n > 0
            {
                tracing::info!(pruned = n, "metering: pruned old usage buckets");
            }
        }
    }
}
