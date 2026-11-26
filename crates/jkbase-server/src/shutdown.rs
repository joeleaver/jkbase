//! Process shutdown. An UPGRADE restart (fresh `.upgrading` flag) drains HTTP and leaves tenant
//! VMs running for the successor to re-adopt; a real shutdown hibernates every running VM.

use crate::{
    LogShipper, PlatformState, VmLifecycle, force_stop_and_cleanup, hibernate_project, l4_runtime,
};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::info;

/// How recently the `.upgrading` flag must have been written for `shutdown_signal` to treat a
/// SIGTERM as an UPGRADE (skip the drain, leave VMs for re-adoption) rather than a real
/// shutdown. A stale flag (deploy crashed after touching it but before `systemctl restart`)
/// falls back to draining — so a later operator `stop` never silently leaks running tenants.
pub(crate) const UPGRADE_FLAG_FRESHNESS_SECS: u64 = 300;

/// Hard ceiling (seconds) on the upgrade-restart HTTP drain (zero-bounce Phase 2). The process is
/// GUARANTEED to `process::exit(0)` within this window of the SIGTERM — event-driven (it exits the
/// instant the proxy + storage in-flight work empties), so an idle box pays ~0. Well under
/// `TimeoutStopSec=120`, and small so a slow/hostile in-flight request can't widen the successor's
/// start delay. Bulk transfers exceeding it are cut at exit (no worse than today). See
/// `docs/zero-bounce-phase2-design.md`.
pub(crate) const DRAIN_GRACE: Duration = Duration::from_secs(5);

/// Path of the upgrade-in-progress flag `deploy-server.sh` writes immediately before
/// `systemctl restart`. Its first line is the epoch second it was written (a second optional
/// line carries the deploy pid, for diagnostics only).
pub(crate) fn upgrade_flag_path(data_dir: &Path) -> PathBuf {
    data_dir.join(".upgrading")
}

/// True iff a FRESH upgrade flag is present (written < [`UPGRADE_FLAG_FRESHNESS_SECS`] ago).
pub(crate) fn upgrade_in_progress(data_dir: &Path) -> bool {
    let Ok(body) = std::fs::read_to_string(upgrade_flag_path(data_dir)) else {
        return false;
    };
    let Some(ts) = body
        .lines()
        .next()
        .and_then(|l| l.trim().parse::<u64>().ok())
    else {
        return false;
    };
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    now.saturating_sub(ts) < UPGRADE_FLAG_FRESHNESS_SECS
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn shutdown_signal(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
    proxy_shutdown: tokio_util::sync::CancellationToken,
    storage_shutdown: tokio_util::sync::CancellationToken,
    auth_shutdown: tokio_util::sync::CancellationToken,
    upgrade_kind: Arc<std::sync::atomic::AtomicBool>,
    l4_registry: l4_runtime::L4PortRegistry,
) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }

    // VM re-adoption §8: an UPGRADE restart (a fresh .upgrading flag) leaves tenant VMs RUNNING for
    // the next process to re-adopt — the zero-bounce goal. Phase 2 ALSO keeps the data plane up:
    // the systemd-owned :80/:443 sockets stay open (new connections queue for the successor) while
    // this process GRACEFULLY DRAINS in-flight HTTP. We must still exit WITHOUT running VmInstance
    // destructors (Drop/kill_on_drop would SIGKILL every survivor); the survivors live in the
    // jkbase-runtime cgroup, untouched by KillMode=mixed. A real shutdown (no fresh flag) falls
    // through and drains/hibernates as before.
    let data_dir = { platform.lock().await.data_dir.clone() };
    if upgrade_in_progress(&data_dir) {
        let n = platform.lock().await.vms.len();
        info!(
            running_vms = n,
            "upgrade restart (.upgrading present) — draining HTTP (proxy+storage+api), leaving \
             tenant VMs running for re-adoption"
        );
        // Stop accepting + begin draining the proxy + storage. The api drains via axum's own
        // graceful shutdown once we RETURN (NOT process::exit inline — that would skip the api
        // drain). Draining touches only connection-level state, never a VmInstance (the proxy's
        // SharedState is disjoint from PlatformState.vms), so no survivor is dropped.
        // Hand our L4 flow identities to the successor BEFORE draining, so a slow drain or the
        // DRAIN_GRACE watchdog can never exit past it. Only on THIS branch: a real shutdown
        // hibernates the VMs, so there is no surviving agent to resume against and a hand-off
        // would be a lie. Best-effort — a failure costs tuple continuity for one upgrade, never
        // correctness.
        // Best-effort AND panic-proof: this runs upstream of `upgrade_kind`, the drain and the
        // DRAIN_GRACE watchdog, so an unwind here would escape into `main`, run `PlatformState`'s
        // destructors and SIGKILL every survivor. Catch it and carry on with the upgrade.
        use futures_util::FutureExt as _;
        if std::panic::AssertUnwindSafe(l4_runtime::snapshot_handover(&l4_registry, &data_dir))
            .catch_unwind()
            .await
            .is_err()
        {
            tracing::error!("l4 handover: snapshot panicked — continuing the upgrade without it");
        }
        proxy_shutdown.cancel();
        storage_shutdown.cancel();
        auth_shutdown.cancel();
        upgrade_kind.store(true, std::sync::atomic::Ordering::SeqCst);
        // Watchdog (adversarial BLOCKER-1): GUARANTEE the process exits within DRAIN_GRACE of the
        // SIGTERM no matter what any drain is doing — axum's graceful shutdown has NO internal
        // timeout, so a hostile tenant holding an authenticated `api.` request open could otherwise
        // stall to TimeoutStopSec (a LONGER gap than Phase 1). exit(0) skips destructors, sparing
        // the jkbase-runtime FCs.
        tokio::spawn(async {
            tokio::time::sleep(DRAIN_GRACE).await;
            tracing::warn!("upgrade drain grace elapsed — exiting (cutting any remaining streams)");
            std::process::exit(0);
        });
        return;
    }

    // Normal shutdown: the VMs hibernate, so no agent survives to resume against. Drop any
    // hand-off rather than leaving the client 5-tuples of every live session on disk.
    l4_runtime::handover::discard(&data_dir);
    info!("shutdown signal received, hibernating running VMs...");

    let running_projects: Vec<String> = {
        let plat = platform.lock().await;
        plat.vm_states
            .iter()
            .filter(|(_, state)| **state == VmLifecycle::Running)
            .map(|(id, _)| id.clone())
            .collect()
    };

    for project_id in &running_projects {
        info!(project = %project_id, "hibernating for shutdown");
        if let Err(e) = hibernate_project(
            project_id,
            platform.clone(),
            routing.clone(),
            shipper.clone(),
            None,
            None,
        )
        .await
        {
            // hibernate_project self-cleans its own wedge/timeout paths; this is a
            // last-resort catch for an unexpected Err, routed through the same helper.
            tracing::error!(project = %project_id, error = %e, "hibernate errored, force stopping");
            force_stop_and_cleanup(project_id, &platform, None).await;
        }
    }

    info!("all VMs hibernated, shutdown complete");
}
