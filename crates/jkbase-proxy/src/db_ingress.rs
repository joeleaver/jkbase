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
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio_rustls::server::TlsStream;
use tracing::{debug, warn};

/// App-level idle watchdog for a DB relay — effectively "never", so a legitimately
/// silent realtime subscription stays open. A DEAD peer is reaped by TCP keepalive ([R9])
/// in ~minutes; drain + revocation are the other teardown paths. (This is NOT the tenant
/// keeping a VM warm for free — that is metered/gauged elsewhere.)
const DB_RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(30 * 24 * 3600);
/// Hard deadline on the handshake→preamble read of an UNAUTHENTICATED connection ([R6]).
const PREAMBLE_DEADLINE: Duration = Duration::from_secs(10);

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
    /// Per-project live-relay cap (bounds owner over-subscription).
    pub per_project_max: usize,
}

impl DbIngress {
    /// Drive one DB reach connection to completion (or drop it). `_drain` is the graceful
    /// drain barrier token held for the connection's life (like the HTTP path); the drain
    /// deadline force-closes registered relays via [`DbRelayRegistry::cancel_all`].
    pub async fn handle(self: Arc<Self>, tls: TlsStream<TcpStream>) {
        if let Err(reason) = self.serve(tls).await {
            debug!(reason, "db reach connection dropped");
        }
    }

    async fn serve(&self, mut tls: TlsStream<TcpStream>) -> Result<(), &'static str> {
        // [R6] Bound unauthenticated work up front.
        let preauth = self
            .preauth
            .clone()
            .try_acquire_owned()
            .map_err(|_| "preauth cap reached")?;

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
        let project_id = ok.project_id;
        let akid = preamble.akid;

        // Authenticated → free the unauth slot; take the post-auth ceilings.
        drop(preauth);
        let _global = self
            .global
            .clone()
            .try_acquire_owned()
            .map_err(|_| "global db cap reached")?;
        if self.registry.conn_count(&project_id) >= self.per_project_max {
            return Err("per-project db cap reached");
        }

        // [R7] AUTH BEFORE WAKE — a woken VM is a real cost; never on an unauth connection.
        let vm_ip = match (self.wake)(project_id.clone()).await {
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
        };

        // Stamp post-wake so the idle loop doesn't hibernate the VM out from under us.
        self.stamp(&project_id).await;

        // Register the live relay: gauge++ (excludes from hibernation, §5) + a cancel
        // token the drain ([R-drain]) and key/project revocation ([R5]) close it through.
        let (guard, cancel) = self.registry.register(&project_id, &akid);

        // Connect the agent backend leg, presenting the splice secret ([R3]).
        let mut backend = self.connect_agent(&vm_ip, &ok.splice_secret).await?;

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
