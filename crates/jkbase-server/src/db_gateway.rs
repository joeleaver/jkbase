//! The app→DB in-guest leg's HOST gateway (P2 §7.6).
//!
//! A **dedicated** project's app runs in the app VM (`AppNoDb` — no co-located rhypedb); its DB
//! runs in the sibling DB VM. Direct app↔DB L2 is closed (bridge port-isolation drops VM↔VM), so
//! the app reaches its DB **host-mediated**: the app agent's in-guest loopback proxy
//! (`127.0.0.1:4200/4201`) dials this gateway on the bridge gateway IP (`172.16.0.1`), and we
//! splice through to the DB VM's agent `/_jkbase/db` — the SAME seam the external `:443` edge uses.
//!
//! ## Authentication = the guest's unforgeable SOURCE IP
//!
//! The L2 source-guard (`install_tap_source_guard`) pins `{ip,mac}↔TAP↔slot` and DROPs any frame
//! whose `--ip-src` isn't the slot's IP, so a guest can only EVER emit its own source IP. The
//! accepted socket's peer IP is therefore an **unspoofable project identity**: `peer_ip →
//! VmAllocation → project`. Cross-tenant reach is impossible by construction — project A cannot
//! present project B's source IP, so it can only ever reach its OWN DB VM.
//!
//! We resolve the project's **current** splice secret host-side (`get_db_splice_secret`, the same
//! store value the console/edge reach path already dials with — always coherent with the DB VM's
//! baked copy since both come from the same deploy) and present it on the DB-agent upgrade ([R3]).
//!
//! ### Deviation from design §7.6 (for the adversarial review)
//!
//! §7.6 listed an app-presented splice secret as *defense-in-depth on top of* the source-IP
//! identity. We DROP it: it is redundant with the unforgeable source IP (any process in the
//! untrusted guest can read `_db_reach.json`, and every guest only ever reaches its OWN DB either
//! way), while it would add a rotation-drift failure mode (the secret rotates every deploy) AND a
//! guest-controlled parse *before* the splice. The source IP is the real, already-enforced
//! boundary; the gateway reads ZERO guest bytes before it authenticates and splices. The
//! host-held secret is still presented to the DB agent, so the loopback DB stays gated exactly as
//! before.
//!
//! ## Ordering (mirrors `db_ingress`, minus TLS/preamble/preauth)
//!
//! accept → global permit → `peer_ip → project` → `get_db_splice_secret` (None ⇒ no managed DB ⇒
//! drop) → `try_register` the relay (per-project cap enforced atomically, and the relay is visible
//! to drain/revocation for the whole setup window) → `wake` the DB VM → agent upgrade (present the
//! secret + the DB port) → splice. Registering under the BASE project keeps BOTH VMs warm while a
//! (possibly byte-silent subscription) relay is live — the idle loop reads the same `conn_count`.

use crate::Store;
use jkbase_control::store::VmAllocation;
use jkbase_proxy::db_relay::DbRelayRegistry;
use jkbase_proxy::{WakeCallback, WakeError};
use std::net::IpAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Total concurrent app→DB leg relays across all projects (host-wide ceiling). Generous — one
/// relay is a cheap spliced socket; the real per-project bound is the registry's per-project cap.
const GLOBAL_MAX: usize = 2048;
/// Per-project live-leg cap. A dedicated app can open many DB connections (an HTTP pool + N
/// subscriptions), but not unbounded — this bounds the fd/relay footprint of one project. The
/// source IP is the project, so this is also the per-source-IP bound.
const PER_PROJECT_MAX: usize = 256;
/// App→DB relays are long-lived (a subscription is byte-silent yet must stay open); a DEAD peer is
/// reaped by TCP keepalive. `30d` ≈ "never" for the app-level idle watchdog, matching the edge.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 3600);
/// Hard deadline on the post-auth backend leg (DB-VM wake + agent TCP connect + HTTP/1.1 upgrade),
/// so a stalled agent can't pin the global permit + gauge on an unbreakable await.
const CONNECT_DEADLINE: Duration = Duration::from_secs(30);
/// Synthetic akid for leg relays in the shared registry. Never a real DB key, so `cancel_key`
/// (external key revocation) never targets these; `cancel_project` / `cancel_all` still do.
const LEG_AKID: &str = "__app_db_leg__";

/// Everything a gateway connection needs, built once and shared (`Arc`) across both listeners.
struct Gateway {
    store: Store,
    wake: WakeCallback,
    registry: Arc<DbRelayRegistry>,
    /// Post-auth global relay ceiling.
    global: Arc<Semaphore>,
    /// TCP port the in-VM agent listens on (`:80`).
    backend_port: u16,
}

/// Bind both gateway ports on the bridge gateway IP and serve forever. Best-effort: a bind failure
/// (no bridge on a dev box, or a stale bind) disables ONLY the in-guest leg — external reach +
/// console still work — and is logged, never fatal. Bound to `172.16.0.1` specifically (NOT
/// `0.0.0.0`), so the gateway is off the public interface; `JKRUNFW` opens the two ports to the
/// bridge, and the per-connection source-IP auth does the rest.
pub async fn serve(store: Store, wake: WakeCallback, registry: Arc<DbRelayRegistry>) {
    use jkbase_common::config::{DB_GATEWAY_HTTP_PORT, DB_GATEWAY_IP, DB_GATEWAY_WIRE_PORT};

    let gw = Arc::new(Gateway {
        store,
        wake,
        registry,
        global: Arc::new(Semaphore::new(GLOBAL_MAX)),
        backend_port: 80,
    });

    // Each listener maps to a fixed rhypedb loopback port on the DB VM (the header the agent
    // splices by): the wire port → 4201, the http port → 4200.
    let wire = accept_loop(gw.clone(), DB_GATEWAY_IP, DB_GATEWAY_WIRE_PORT, 4201);
    let http = accept_loop(gw.clone(), DB_GATEWAY_IP, DB_GATEWAY_HTTP_PORT, 4200);
    tokio::join!(wire, http);
}

/// Accept loop for one gateway port. `db_port` is the rhypedb loopback port the DB-VM agent must
/// splice to (presented as `x-jkbase-db-port`).
async fn accept_loop(gw: Arc<Gateway>, ip: &str, port: u16, db_port: u16) {
    let listener = match TcpListener::bind((ip, port)).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, %ip, port, "app→DB gateway: bind failed — in-guest leg disabled");
            return;
        }
    };
    info!(%ip, port, db_port, "app→DB gateway listening");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Back off so a transient accept errno (fd exhaustion) can't busy-spin.
                warn!(error = %e, port, "app→DB gateway: accept error");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        let gw = gw.clone();
        tokio::spawn(async move {
            if let Err(reason) = gw.handle(stream, peer.ip(), db_port).await {
                debug!(peer = %peer.ip(), db_port, reason, "app→DB gateway connection dropped");
            }
        });
    }
}

impl Gateway {
    async fn handle(
        &self,
        guest: TcpStream,
        peer_ip: IpAddr,
        db_port: u16,
    ) -> Result<(), &'static str> {
        let _ = jkbase_wsproxy::set_relay_keepalive(&guest); // guest leg keepalive

        // Bound total in-flight relays BEFORE any project work — a cheap global gate.
        let _global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| "global gateway cap reached")?;

        // [AUTH] peer_ip → project. The L2 source-guard makes the source IP unforgeable, so this
        // is a sound project identity. An app VM's alloc carries the BASE project id, which is what
        // `get_db_splice_secret` / `wake` expect. No match (e.g. an alloc churn window) ⇒ drop.
        let project_id = self
            .project_for_ip(peer_ip)
            .ok_or("source ip maps to no allocation")?;

        // No managed DB for this project ⇒ nothing to reach ⇒ drop (fail-closed). Also fences a
        // non-DB project's guest that dials the (bridge-wide-open) gateway.
        let splice_secret = self
            .store
            .get_db_splice_secret(&project_id)
            .map_err(|_| "splice secret lookup failed")?
            .ok_or("no managed database for this project")?;

        // Reserve the relay slot NOW — BEFORE the wake `.await` — so (a) the per-project cap can't
        // be TOCTOU'd by concurrent connects and (b) the relay is visible to cancel_project /
        // cancel_all for the whole setup window. Registered under the BASE project with no tenant
        // (the app→DB leg is internal — it must NOT be refused by the external-reach warm-VM
        // quota; the app VM is already warm and its DB VM being warm is inherent to the tier) and a
        // synthetic akid. `conn_count(base) > 0` then keeps BOTH the app VM and the `{base}.db` VM
        // out of idle hibernation while a (possibly byte-silent subscription) relay is live.
        let (guard, cancel) = self
            .registry
            .try_register(&project_id, None, LEG_AKID, PER_PROJECT_MAX, 0, 0)
            .map_err(|_| "per-project db leg cap reached")?;

        // [R7] AUTH BEFORE WAKE — a woken VM is real cost. Selectable on `cancel` so a project
        // delete mid-wake aborts instead of waiting out a full restore. `wake` resolves the reach
        // target (the `.db` VM for a dedicated project) and boots it.
        let vm_ip = tokio::select! {
            _ = cancel.cancelled() => return Err("cancelled during wake"),
            woke = (self.wake)(project_id.clone()) => match woke {
                Ok(ip) => ip,
                Err(WakeError::OverQuota(_)) => return Err("over quota"),
                Err(WakeError::Unavailable(_)) => return Err("unavailable"),
                Err(WakeError::Gone(_)) => return Err("gone"),
            },
        };

        // Connect the DB-VM agent backend leg, presenting the host-held splice secret ([R3]) + the
        // target rhypedb port. Bounded by a deadline AND selectable on `cancel`.
        let backend = tokio::select! {
            _ = cancel.cancelled() => return Err("cancelled during agent connect"),
            res = tokio::time::timeout(
                CONNECT_DEADLINE,
                self.connect_agent(&vm_ip, &splice_secret, db_port),
            ) => match res {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err("agent connect timeout"),
            },
        };

        // Splice until EOF / idle / cancel.
        jkbase_wsproxy::relay_bidirectional_hooked(
            guest,
            backend,
            RELAY_IDLE_TIMEOUT,
            jkbase_wsproxy::RelayHooks {
                cancel: Some(cancel),
                on_activity: None,
            },
        )
        .await;

        drop(guard); // gauge-- exactly when the relay ends
        drop(_global);
        Ok(())
    }

    /// The project owning `peer_ip`, per the (source-guard-pinned) allocation table. `O(n)` over
    /// the VM allocations — fine per-connection (a small table; the tenant's HTTP client keeps the
    /// connection alive, and the native wire is one long-lived connection).
    fn project_for_ip(&self, peer_ip: IpAddr) -> Option<String> {
        project_for_ip_in(&self.store.list_vm_allocations().ok()?, peer_ip)
    }

    /// HTTP/1.1 `Upgrade` to `<vm_ip>:80/_jkbase/db` presenting the splice secret + the rhypedb
    /// loopback port; on `101` reclaim the raw upgraded stream. Mirrors the edge's
    /// `db_ingress::connect_agent`, adding the host-set `x-jkbase-db-port`. The DB stays
    /// loopback-only inside the DB VM — its agent is the sole mediator.
    async fn connect_agent(
        &self,
        vm_ip: &str,
        splice_secret: &str,
        db_port: u16,
    ) -> Result<hyper_util::rt::TokioIo<hyper::upgrade::Upgraded>, &'static str> {
        use http_body_util::Full;
        use hyper::body::Bytes;
        let stream = TcpStream::connect((vm_ip, self.backend_port))
            .await
            .map_err(|_| "agent connect")?;
        let _ = jkbase_wsproxy::set_relay_keepalive(&stream);
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|_| "agent handshake")?;
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
        let req = hyper::Request::builder()
            .method("GET")
            .uri("/_jkbase/db")
            .header("host", vm_ip)
            .header("connection", "upgrade")
            .header("upgrade", "jkbase-db")
            .header("x-jkbase-db-secret", splice_secret)
            .header("x-jkbase-db-port", db_port.to_string())
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|_| "agent req build")?;
        let mut resp = sender.send_request(req).await.map_err(|_| "agent send")?;
        if resp.status() != hyper::StatusCode::SWITCHING_PROTOCOLS {
            // 404 ⇒ the agent has no/mismatched secret (fail-closed); 400 ⇒ bad db port.
            warn!(status = %resp.status(), "app→DB gateway: agent refused db splice upgrade");
            return Err("agent no 101");
        }
        let upgraded = hyper::upgrade::on(&mut resp)
            .await
            .map_err(|_| "agent upgrade")?;
        Ok(hyper_util::rt::TokioIo::new(upgraded))
    }
}

/// Match a source IP to its owning project among the allocation table — the pinned, unforgeable
/// identity (the L2 source-guard guarantees `peer_ip` is the slot's own IP). Pure (the store read
/// is the caller's), so the exact-match discipline is unit-testable. An app VM's alloc carries the
/// BASE project id; a `.db` alloc carries `{base}.db` — but only app VMs run the loopback proxy, so
/// in practice this resolves to the base id `get_db_splice_secret`/`wake_db_reach` expect.
fn project_for_ip_in(allocs: &[VmAllocation], peer_ip: IpAddr) -> Option<String> {
    let want = peer_ip.to_string();
    allocs
        .iter()
        .find(|a| a.ip == want)
        .map(|a| a.project_id.clone())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn alloc(project_id: &str, ip: &str) -> VmAllocation {
        VmAllocation {
            project_id: project_id.to_string(),
            ip: ip.to_string(),
            tap_device: "tap0".to_string(),
            mac: "AA:FC:00:00:00:02".to_string(),
            host_id: String::new(),
            placement_epoch: 0,
        }
    }

    #[test]
    fn project_for_ip_exact_match_only() {
        let allocs = vec![
            alloc("foo", "172.16.0.2"),
            alloc("bar", "172.16.0.3"),
            // A dedicated project's DB VM alloc carries the `.db` id — present but only ever
            // matched by the DB VM's own (non-proxying) source IP.
            alloc("foo.db", "172.16.0.4"),
        ];

        // The app VM's source IP resolves to the BASE project id.
        assert_eq!(
            project_for_ip_in(&allocs, "172.16.0.2".parse().unwrap()).as_deref(),
            Some("foo")
        );
        assert_eq!(
            project_for_ip_in(&allocs, "172.16.0.3".parse().unwrap()).as_deref(),
            Some("bar")
        );
        // The `.db` IP maps to `foo.db` (which has no splice secret of its own → the caller drops).
        assert_eq!(
            project_for_ip_in(&allocs, "172.16.0.4".parse().unwrap()).as_deref(),
            Some("foo.db")
        );
        // An IP with no allocation (churn window / spoof attempt the source-guard already blocks)
        // maps to nothing → the caller drops the connection.
        assert_eq!(
            project_for_ip_in(&allocs, "172.16.0.9".parse().unwrap()),
            None
        );
        // No prefix/substring confusion: `172.16.0.2` must not match `172.16.0.20`-style entries.
        let allocs2 = vec![alloc("wide", "172.16.0.20")];
        assert_eq!(
            project_for_ip_in(&allocs2, "172.16.0.2".parse().unwrap()),
            None
        );
    }
}
