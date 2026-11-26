//! Idle hibernation: the loop that hibernates a project once neither HTTP activity, a live
//! managed-DB relay nor an established L4 flow has touched it for the idle timeout.

use crate::{LogShipper, PlatformState, VmLifecycle, vm_identity};
use crate::hibernate::{hibernate_project};
use jkbase_proxy::ActivityTracker;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::info;

pub(crate) async fn idle_detection_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    activity: ActivityTracker,
    idle_timeout: Duration,
    shipper: Arc<LogShipper>,
    db_registry: Option<Arc<jkbase_proxy::db_relay::DbRelayRegistry>>,
    // The L4 plane contributes its OWN keep-warm signals (an established-flow gauge + an
    // un-throttled last-datagram clock), read here and ANDed into `should_hibernate` — NEVER
    // written back into the shared `activity` tracker, which would back-date another plane's
    // hibernate clock and snapshot an HTTP/DB-active project mid-serve (§3(d) mechanics H5).
    l4_plane: Option<Arc<jkbase_proxy::l4_plane::L4Plane>>,
) {
    let check_interval = Duration::from_secs(60);

    loop {
        tokio::time::sleep(check_interval).await;

        // Seed a baseline for any Running VM the proxy hasn't tracked. Activity is
        // only recorded on proxy requests, so a project that receives none — e.g. a
        // cron-only function project, woken host->agent — would otherwise never be a
        // hibernation candidate and never scale to zero. Seeding `now` gives it an
        // idle clock that ages out after `idle_timeout` of no further activity.
        {
            let running: Vec<String> = {
                let plat = platform.lock().await;
                plat.vm_states
                    .iter()
                    .filter(|(_, s)| **s == VmLifecycle::Running)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            let mut tracker = activity.write().await;
            let now = Instant::now();
            for id in running {
                tracker.entry(id).or_insert(now);
            }
        }

        let candidates: Vec<String> = {
            let tracker = activity.read().await;
            let now = Instant::now();
            tracker
                .iter()
                .filter(|(_, last)| now.duration_since(**last) > idle_timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for project_id in candidates {
            let should_hibernate = {
                let plat = platform.lock().await;
                plat.vm_states.get(&project_id) == Some(&VmLifecycle::Running)
            }
            // §5: never hibernate a project with a LIVE managed-DB relay — a realtime
            // subscription can be open but byte-silent, so last-byte activity alone would
            // scale it to zero out from under the connection. Relays are keyed by the BASE
            // project, so a dedicated DB VM (`{id}.db`) candidate is kept warm by the same count.
            && db_registry
                .as_ref()
                .map(|r| r.conn_count(vm_identity::base_project_id(&project_id)) == 0)
                .unwrap_or(true)
            // §3(d): keep an L4 project warm ONLY while it has an ESTABLISHED flow (a byte-silent
            // but live inbound-only/streaming app stays warm via conn_count > 0). PROVISIONAL
            // (unpromoted, spoofable) flows deliberately do NOT count — they carry their own 5s
            // timeout and must not pin the VM warm, else a spoof flood that never establishes would
            // hold it warm for the full idle_timeout (P0-L4-12 / §3(d)). When established flows
            // drain, conn_count → 0 (the per-port idle sweep evicts them) and the VM hibernates on
            // the normal shared-seed idle path — never back-dating the shared ActivityTracker.
            && l4_plane
                .as_ref()
                .map(|p| p.conn_count(vm_identity::base_project_id(&project_id)) == 0)
                .unwrap_or(true);

            if should_hibernate {
                info!(project = %project_id, "idle timeout, hibernating");
                if let Err(e) = hibernate_project(
                    &project_id,
                    platform.clone(),
                    routing.clone(),
                    shipper.clone(),
                    db_registry.as_ref(),
                    l4_plane.as_ref(),
                )
                .await
                {
                    tracing::error!(project = %project_id, error = %e, "failed to hibernate");
                }

                let mut tracker = activity.write().await;
                tracker.remove(&project_id);
            }
        }
    }
}
