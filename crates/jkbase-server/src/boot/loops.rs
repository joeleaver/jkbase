//! The background loops: log shipping, nightly DB backups, idle hibernation, scheduled
//! functions and metering.

use super::Planes;
use crate::cli::Args;
use crate::db_ops::{DbBackupCtx, db_backup_nightly_loop};
use crate::idle::idle_detection_loop;
use crate::log_shipper::log_shipper_loop;
use crate::metering_loop::metering_loop;
use crate::scheduler::scheduler_loop;
use jkbase_proxy::ActivityTracker;
use jkbase_proxy::db_relay::DbRelayRegistry;
use jkbase_proxy::l4_plane::L4Plane;
use std::sync::Arc;
use std::time::Duration;
use tracing::info;

pub(crate) fn spawn_loops(
    args: &Args,
    planes: &Planes,
    activity_tracker: &ActivityTracker,
    db_backup_ctx: &DbBackupCtx,
    db_relay_registry: &Arc<DbRelayRegistry>,
    l4_plane: &Arc<L4Plane>,
) {
    // Spawn log shipper loop (pulls guest logs into the persistent store)
    tokio::spawn(log_shipper_loop(
        planes.platform.clone(),
        planes.shipper.clone(),
    ));

    // Nightly automatic managed-DB backups ([RB12]).
    tokio::spawn(db_backup_nightly_loop(db_backup_ctx.clone()));

    // Spawn idle detection loop
    if args.idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(args.idle_timeout_secs);
        info!(
            timeout_secs = args.idle_timeout_secs,
            "idle detection enabled"
        );
        tokio::spawn(idle_detection_loop(
            planes.platform.clone(),
            planes.routing.clone(),
            activity_tracker.clone(),
            idle_timeout,
            planes.shipper.clone(),
            Some(db_relay_registry.clone()),
            Some(l4_plane.clone()),
        ));
    }

    // Spawn the scheduled-functions loop (host-driven cron). Reads the durable
    // SCHEDULES registry each tick, wakes + invokes due functions.
    tokio::spawn(scheduler_loop(
        planes.platform.clone(),
        planes.routing.clone(),
        planes.domains.clone(),
        planes.shipper.clone(),
        activity_tracker.clone(),
    ));

    // Spawn the metering + quota-enforcement loop. Samples per-project CPU,
    // bandwidth, and storage into hourly rollup buckets and hibernates +
    // blocks projects that exceed their monthly bandwidth cap.
    tokio::spawn(metering_loop(
        planes.platform.clone(),
        planes.routing.clone(),
        planes.shipper.clone(),
        Some(db_relay_registry.clone()),
        Some(l4_plane.clone()),
    ));
}
