//! Host-side data planes beside the proxy: the app→DB gateway, the guest DNS forwarder and
//! L4 UDP ingress.

use super::Planes;
use crate::l4_runtime::{self, L4PortRegistry};
use crate::wake::{app_wake_callback, db_reach_wake_callback};
use crate::{db_gateway, dns_forwarder};
use jkbase_control::store::Store;
use jkbase_proxy::db_relay::DbRelayRegistry;
use jkbase_proxy::l4_plane::L4Plane;
use std::sync::Arc;

pub(crate) async fn spawn_data_plane(
    store: &Store,
    planes: &Planes,
    db_relay_registry: &Arc<DbRelayRegistry>,
) -> (L4PortRegistry, Arc<L4Plane>) {
    // P2 §7.6 — the app→DB in-guest leg's host gateway. Lets a dedicated project's app VM reach
    // its sibling DB VM on the same `127.0.0.1:4200/4201` as co-located, host-mediated over the
    // bridge gateway IP and authenticated by the guest's unforgeable source IP. Best-effort bind
    // (see `db_gateway::serve`); it wakes like the proxy's DB edge (the dedicated `.db` target).
    {
        let store = store.clone();
        let gw_wake = db_reach_wake_callback(
            planes.platform.clone(),
            planes.routing.clone(),
            planes.domains.clone(),
            planes.shipper.clone(),
        );
        let registry = db_relay_registry.clone();
        // This host's id — the gateway resolves peer_ip→project only among THIS host's allocations
        // ([R3], HA IP-collision safety); empty on single-node/pre-HA (matches every alloc).
        let gw_host_id = planes.platform.lock().await.host_id.clone();
        tokio::spawn(async move { db_gateway::serve(store, gw_wake, registry, gw_host_id).await });
    }

    // Host DNS forwarder — answers runtime-guest `/etc/resolv.conf` queries on `172.16.0.1:53` and
    // relays them to the host's own resolver. Replaces systemd-resolved's `DNSStubListenerExtra`
    // (setup-bridge.sh removes the drop-in + restarts resolved to hand off the port in the server's
    // ExecStartPre), so DNS is jkbase-owned: bound to this process (no boot-order race), per-guest
    // rate-limited, logged, and attributed by unforgeable source IP. Best-effort bind (mirrors the
    // DB gateway). NOT a containment boundary — server-app egress is open NAT — it is observability
    // + abuse-control + listener ownership (see dns_forwarder.rs).
    {
        let store = store.clone();
        let dns_host_id = planes.platform.lock().await.host_id.clone();
        tokio::spawn(async move { dns_forwarder::serve(store, dns_host_id).await });
    }

    // L4 UDP scale-to-zero ingress — the plane-global throttle/egress controller + the reconcile
    // loop that materializes `[l4.*]` port allocations into live edge sockets + the datagram pump.
    // The plane is shared with the idle + metering loops (they read its established-flow gauge,
    // last-activity clock, drop counters, and reflection-suspected kill-switch flags). It wakes the
    // APP VM like HTTP routing does — L4 ports are app-VM only, so a dedicated project's DB VM must
    // never receive its datagrams; Axis-1/Axis-2 abuse bounds live inside the plane + pump, keyed on base-project/tenant/dest-IP
    // — never the spoofable source (design §3(c)).
    // Live L4 ports, so an UPGRADE shutdown can hand its flow identities to the successor: the
    // tenant VM survives a zero-bounce restart, so its agent still holds every loopback socket, and
    // resuming the identities is what keeps the app-visible tuples from moving underneath it.
    let l4_registry: l4_runtime::L4PortRegistry = Default::default();
    let l4_plane: Arc<jkbase_proxy::l4_plane::L4Plane> = {
        let l4_wake = app_wake_callback(
            planes.platform.clone(),
            planes.routing.clone(),
            planes.domains.clone(),
            planes.shipper.clone(),
        );
        let plane = jkbase_proxy::l4_plane::L4Plane::new(Default::default(), l4_wake);
        let (l4_host_id, l4_data_dir) = {
            let plat = planes.platform.lock().await;
            (plat.host_id.clone(), plat.data_dir.clone())
        };
        tokio::spawn(l4_runtime::serve(
            store.clone(),
            planes.routing.clone(),
            plane.clone(),
            l4_host_id,
            l4_data_dir.clone(),
            l4_registry.clone(),
        ));
        plane
    };
    (l4_registry, l4_plane)
}
