//! Managed-DB reach-plane edge: the ALPN-demuxed `:443` DB relay path (D3).
//!
//! `serve_https` hands a completed TLS connection here iff it negotiated the `jkbase-db`
//! ALPN. The step sequence is the security spine (§2): require a `.db.{domain}` SNI
//! ([R6]) → derive the edge's `tls-exporter` value → read the bounded preamble ([R6]) →
//! channel-bind it ([R-replay]) → authenticate the key (lookup/verify/owner-rebind/
//! SNI==key-project, [R1]/[R2]/[R4]) → **only then** wake the VM ([R7]) → connect the
//! agent's `/_jkbase/db` presenting the splice secret ([R3]) → register the relay
//! (gauge + cancel token) → splice. Any failure drops the connection touching no backend.

use crate::db_preamble::{self, DB_ALPN, EXPORTER_LABEL, EXPORTER_LEN};
use crate::db_relay::DbRelayRegistry;
use crate::{ActivityTracker, DbAuthCallback, WakeCallback, WakeError};
use http_body_util::Full;
use hyper::StatusCode;
use hyper::body::Bytes;
use hyper_util::rt::TokioIo;
use jkbase_wsproxy::{RelayHooks, relay_bidirectional_hooked, set_relay_keepalive};
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

/// A per-source-IP concurrency limiter for the UNAUTHENTICATED preamble window ([R6]). The
/// global `preauth` semaphore bounds total in-flight handshakes but has no per-IP dimension,
/// so a single host could open `db_preauth_max` connections that each hold a slot for the
/// full `PREAMBLE_DEADLINE` and deny the DB reach plane to every other tenant. This caps how
/// many concurrent pre-auth reads one IP may hold; a permit is released (RAII) the instant
/// the connection authenticates or drops.
pub struct PerIpLimiter {
    counts: Mutex<HashMap<IpAddr, u32>>,
    max: u32,
}

impl PerIpLimiter {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Self {
            counts: Mutex::new(HashMap::new()),
            max: max.max(1) as u32,
        })
    }

    /// Reserve a pre-auth slot for `ip`, or `None` if the IP is already at its cap.
    fn try_acquire(self: &Arc<Self>, ip: IpAddr) -> Option<IpPermit> {
        let mut counts = self.counts.lock().unwrap();
        let n = counts.entry(ip).or_insert(0);
        if *n >= self.max {
            return None;
        }
        *n += 1;
        Some(IpPermit {
            limiter: self.clone(),
            ip,
        })
    }
}

/// RAII pre-auth slot: decrements its IP's count on drop (pruning the entry at zero so the
/// map can't grow unbounded across distinct source IPs).
struct IpPermit {
    limiter: Arc<PerIpLimiter>,
    ip: IpAddr,
}

impl Drop for IpPermit {
    fn drop(&mut self) {
        let mut counts = self.limiter.counts.lock().unwrap();
        if let Some(n) = counts.get_mut(&self.ip) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.ip);
            }
        }
    }
}

/// App-level idle watchdog for a DB relay — effectively "never", so a legitimately
/// silent realtime subscription stays open. A DEAD peer is reaped by TCP keepalive ([R9])
/// in ~minutes; drain + revocation are the other teardown paths. NOTE: an idle relay keeps
/// its own VM warm (conn_count>0 excludes it from hibernation) at ~zero metered cost — the
/// same pre-existing property as any idle HTTP/WS connection to one's own project, and bounded
/// to the owner's OWN projects by the [R1] owner re-bind, NOT a cross-tenant lever. A
/// per-tenant warm-VM quota is the platform-wide fix (tracked on Overboard, not seam-specific).
const DB_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 3600);
/// Hard deadline on the handshake→preamble read of an UNAUTHENTICATED connection ([R6]).
const PREAMBLE_DEADLINE: Duration = Duration::from_secs(10);
/// Hard deadline on the post-auth backend leg (agent TCP connect + HTTP/1.1 upgrade). A
/// woken agent that accepts the TCP but stalls its `101` must not pin the shared global
/// permit + the gauge entry forever on an unbreakable await. Sized well above a healthy
/// wake+upgrade but far below "indefinite".
const CONNECT_DEADLINE: Duration = Duration::from_secs(20);

/// The edge half of the reach plane. Built once (in `serve`) from the proxy config and
/// shared across all DB connections.
pub struct DbIngress {
    pub domain: Arc<String>,
    pub auth: DbAuthCallback,
    pub wake: WakeCallback,
    pub registry: Arc<DbRelayRegistry>,
    pub activity: Option<ActivityTracker>,
    /// TCP port the in-VM agent listens on (`:80`).
    pub backend_port: u16,
    /// Total concurrent live DB relays (post-auth ceiling).
    pub global: Arc<Semaphore>,
    /// Concurrent UNAUTHENTICATED handshake→preamble reads — bounds the flood the public
    /// `:443` takes from the whole internet, which the post-auth per-project cap can't ([R6]).
    pub preauth: Arc<Semaphore>,
    /// Per-source-IP dimension of the preauth bound, so one host can't hold every global
    /// slot for the preamble deadline ([R6]).
    pub per_ip: Arc<PerIpLimiter>,
    /// Per-project live-relay cap (bounds owner over-subscription).
    pub per_project_max: usize,
}

impl DbIngress {
    /// Drive one DB reach connection to completion (or drop it). `peer_ip` is the accepted
    /// socket's source address, used for the per-IP pre-auth cap ([R6]). The connection's
    /// task holds the graceful-drain barrier permit for its life (like the HTTP path); the
    /// drain deadline force-closes registered relays via [`DbRelayRegistry::cancel_all`].
    pub async fn handle(self: Arc<Self>, tls: TlsStream<TcpStream>, peer_ip: IpAddr) {
        if let Err(reason) = self.serve(tls, peer_ip).await {
            debug!(reason, "db reach connection dropped");
        }
    }

    async fn serve(&self, mut tls: TlsStream<TcpStream>, peer_ip: IpAddr) -> Result<(), &'static str> {
        // [R6] Bound unauthenticated work up front — globally AND per source IP, so one host
        // can't hold every global slot for the full preamble deadline. Both permits are held
        // only across the unauthenticated preamble read and released the instant we auth.
        let preauth = self
            .preauth
            .clone()
            .try_acquire_owned()
            .map_err(|_| "preauth cap reached")?;
        let ip_permit = self
            .per_ip
            .try_acquire(peer_ip)
            .ok_or("per-ip preauth cap reached")?;

        // Pull the negotiated ALPN + SNI + our exporter off the completed handshake.
        let (sni, edge_exporter) = {
            let (io, conn) = tls.get_ref();
            // Defensive: serve_https only routes db-ALPN here, but re-check.
            if conn.alpn_protocol() != Some(DB_ALPN) {
                return Err("not db alpn");
            }
            let _ = set_relay_keepalive(io); // client leg keepalive [R9]
            let sni = conn.server_name().ok_or("no sni")?.to_string();
            let exp = conn
                .export_keying_material([0u8; EXPORTER_LEN], EXPORTER_LABEL, None)
                .map_err(|_| "exporter export failed")?;
            (sni, exp)
        };

        // [R6] Require exactly one label before `.db.{domain}` — the claimed project.
        let suffix = format!(".db.{}", self.domain);
        let claimed = sni.strip_suffix(&suffix).ok_or("sni not .db.<domain>")?;
        if claimed.is_empty() || claimed.contains('.') {
            return Err("sni not single-label under .db");
        }
        let claimed = claimed.to_string();

        // [R6] Bounded, deadlined preamble read. Opens NO backend.
        let (preamble, leftover) =
            match tokio::time::timeout(PREAMBLE_DEADLINE, db_preamble::read_preamble(&mut tls))
                .await
            {
                Ok(Ok(p)) => p,
                Ok(Err(_)) => return Err("preamble parse"),
                Err(_) => return Err("preamble deadline"),
            };

        // [R-replay] Channel-bind: the preamble must carry THIS session's exporter.
        if !db_preamble::ct_eq(&edge_exporter, &preamble.exporter) {
            return Err("exporter mismatch (replay?)");
        }

        // Authenticate: lookup akid → verify secret fingerprint → SNI==key-project ([R1])
        // → owner re-bind. The AUTHORITATIVE project is the KEY's, returned here.
        let ok = (self.auth)(&preamble.akid, &preamble.secret, &claimed).ok_or("auth rejected")?;
        let project_id = ok.project_id.clone();
        let tenant_id = ok.tenant_id.clone();
        let warm_vm_max = ok.warm_vm_max as usize;
        let warm_relay_max = ok.warm_relay_max as usize;
        let akid = preamble.akid.clone();

        // Authenticated → free the unauth slots (global + per-IP); take the post-auth ceilings.
        drop(preauth);
        drop(ip_permit);
        let _global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| "global db cap reached")?;

        // Reserve the live-relay slot NOW — BEFORE any wake `.await` — with the per-project
        // cap enforced atomically inside `try_register`. Two invariants ride on this order:
        //  • the per-project cap can't be TOCTOU'd by concurrent connects that all read a
        //    stale `conn_count < max` before any of them registers, and
        //  • the relay is visible to `cancel_key`/`cancel_project` for the ENTIRE setup
        //    window (wake + connect), so a revocation during setup tears it down ([R5]).
        // Enforces BOTH the per-project cap AND the per-tenant warm-VM quota atomically
        // under the registry lock, refusing BEFORE the wake `.await` — an over-quota
        // connection never costs a VM boot. The per-tenant refusal is the warm-VM quota:
        // an owner can't pin more than `warm_vm_max` of their VMs warm via idle DB
        // connections.
        let (guard, cancel) = self
            .registry
            .try_register(
                &project_id,
                tenant_id.as_deref(),
                &akid,
                self.per_project_max,
                warm_vm_max,
                warm_relay_max,
            )
            .map_err(|r| match r {
                crate::db_relay::RelayRejected::PerProject => "per-project db cap reached",
                crate::db_relay::RelayRejected::PerTenant => "tenant warm-VM quota reached",
                crate::db_relay::RelayRejected::PerTenantRelays => "tenant relay quota reached",
            })?;

        // Close the auth→register cross-thread race ([R5]): a revoke on another runtime
        // thread that ran between the auth read above and the register just now would have
        // (a) missed this connection (nothing registered to cancel) AND (b) deleted the key.
        // Re-validate now that we ARE registered: any `cancel_key` that runs after our
        // register will find us; any `delete` that ran before this re-check is seen here. So
        // no interleaving lets a revoked key keep a live relay. `guard` drops (deregisters)
        // on the early return.
        if (self.auth)(&preamble.akid, &preamble.secret, &claimed).is_none() {
            return Err("key revoked during setup");
        }

        // [R7] AUTH BEFORE WAKE — a woken VM is a real cost; never on an unauth connection.
        // Selectable on `cancel` so a revocation mid-wake aborts instead of waiting out a
        // full VM restore.
        let vm_ip = tokio::select! {
            _ = cancel.cancelled() => return Err("cancelled during wake"),
            woke = (self.wake)(project_id.clone()) => match woke {
                Ok(ip) => ip,
                Err(WakeError::OverQuota(m)) => {
                    debug!(project = %project_id, %m, "db wake over quota");
                    return Err("over quota");
                }
                Err(WakeError::Unavailable(m)) => {
                    debug!(project = %project_id, %m, "db wake unavailable");
                    return Err("unavailable");
                }
                Err(WakeError::Gone(m)) => {
                    debug!(project = %project_id, %m, "db wake gone");
                    return Err("gone");
                }
                Err(WakeError::RateLimited(m)) => {
                    // Throttled — transient from the caller's view (retry), like Unavailable.
                    debug!(project = %project_id, %m, "db wake rate limited");
                    return Err("rate limited");
                }
            },
        };

        // Stamp post-wake so the idle loop doesn't hibernate the VM out from under us.
        self.stamp(&project_id).await;

        // Connect the agent backend leg, presenting the splice secret ([R3]). Bounded by a
        // deadline AND selectable on `cancel`, so a stalled agent (or a revocation) can't
        // pin the shared global permit + gauge on an unbreakable await.
        let mut backend = tokio::select! {
            _ = cancel.cancelled() => return Err("cancelled during agent connect"),
            res = tokio::time::timeout(
                CONNECT_DEADLINE,
                self.connect_agent(&vm_ip, &ok.splice_secret),
            ) => match res {
                Ok(Ok(b)) => b,
                Ok(Err(e)) => return Err(e),
                Err(_) => return Err("agent connect timeout"),
            },
        };

        // [R-relay] Flush any bytes the client pipelined after the preamble first.
        if !leftover.is_empty() && backend.write_all(&leftover).await.is_err() {
            return Err("backend leftover write");
        }

        // Splice until EOF / idle / cancel. Byte flow re-stamps activity (throttled, §5).
        let on_activity = self.on_activity(&project_id);
        relay_bidirectional_hooked(
            tls,
            backend,
            DB_RELAY_IDLE_TIMEOUT,
            RelayHooks {
                cancel: Some(cancel),
                on_activity,
            },
        )
        .await;

        drop(guard); // gauge-- exactly when the relay ends
        drop(_global);
        Ok(())
    }

    /// HTTP/1.1 `Upgrade` to `<vm_ip>:80/_jkbase/db` presenting the splice secret; on `101`
    /// reclaim the raw upgraded stream. The DB stays loopback-only inside the VM — the
    /// agent is the sole mediator.
    async fn connect_agent(
        &self,
        vm_ip: &str,
        splice_secret: &str,
    ) -> Result<TokioIo<hyper::upgrade::Upgraded>, &'static str> {
        let stream = TcpStream::connect((vm_ip, self.backend_port))
            .await
            .map_err(|_| "agent connect")?;
        let _ = set_relay_keepalive(&stream);
        let io = TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io)
            .await
            .map_err(|_| "agent handshake")?;
        // Drive the connection so the upgrade can complete; reclaim the raw stream from 101.
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
            .body(Full::<Bytes>::new(Bytes::new()))
            .map_err(|_| "agent req build")?;
        let mut resp = sender.send_request(req).await.map_err(|_| "agent send")?;
        if resp.status() != StatusCode::SWITCHING_PROTOCOLS {
            // A 404 here means the agent has no/mismatched splice secret (fail-closed) —
            // a benign misconfig, or an isolation-probe that lacks the secret.
            warn!(status = %resp.status(), "agent refused db splice upgrade");
            return Err("agent no 101");
        }
        let upgraded = hyper::upgrade::on(&mut resp)
            .await
            .map_err(|_| "agent upgrade")?;
        Ok(TokioIo::new(upgraded))
    }

    async fn stamp(&self, project_id: &str) {
        if let Some(act) = &self.activity {
            act.write()
                .await
                .insert(project_id.to_string(), Instant::now());
        }
    }

    /// A throttled activity-stamp callback for the relay (spawns the async map write; the
    /// relay throttles calls to `ACTIVITY_STAMP_INTERVAL`, so this is cheap).
    fn on_activity(&self, project_id: &str) -> Option<Arc<dyn Fn() + Send + Sync>> {
        let act = self.activity.clone()?;
        let pid = project_id.to_string();
        Some(Arc::new(move || {
            let act = act.clone();
            let pid = pid.clone();
            tokio::spawn(async move {
                act.write().await.insert(pid, Instant::now());
            });
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn per_ip_limiter_caps_one_ip_and_releases_on_drop() {
        let lim = PerIpLimiter::new(2);
        let a: IpAddr = "203.0.113.7".parse().unwrap();
        let b: IpAddr = "203.0.113.8".parse().unwrap();

        let p1 = lim.try_acquire(a).unwrap();
        let p2 = lim.try_acquire(a).unwrap();
        // Third concurrent pre-auth from the SAME ip is refused...
        assert!(lim.try_acquire(a).is_none());
        // ...but a different source ip has its own budget.
        let _pb = lim.try_acquire(b).unwrap();

        // Releasing a slot (RAII) re-opens capacity for that ip.
        drop(p1);
        let p3 = lim.try_acquire(a).unwrap();
        assert!(lim.try_acquire(a).is_none());

        // Draining an ip to zero prunes its map entry (no unbounded growth across IPs).
        drop(p2);
        drop(p3);
        assert!(lim.counts.lock().unwrap().get(&a).is_none());
    }

    #[test]
    fn per_ip_limiter_min_one() {
        // A zero/absurd config still admits at least one connection.
        let lim = PerIpLimiter::new(0);
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        assert!(lim.try_acquire(a).is_some());
    }
}
