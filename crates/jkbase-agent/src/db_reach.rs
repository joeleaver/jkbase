//! The host→agent managed-DB reach seam ([R3]/[RB*]): every `/_jkbase/db*` endpoint the HOST
//! drives over the VM's eth0 (reach-plane splice, backup pull, restore push, console query /
//! schema / status, the admin `rewrite-covers` pass) plus the dedicated tier's in-guest app→DB
//! loopback leg. The DB itself stays loopback-only: this module is the sole in-VM path to it,
//! and every host-facing endpoint is gated on the per-deploy splice secret (fail-closed 404).
//! `/admin/*` is reached ONLY on hard-coded paths with the in-guest admin token, which never
//! leaves the guest.

use crate::container_supervisor::{self, ContainerSupervisor};
use crate::{AgentState, not_found_response, upgrade_permits};
use anyhow::{Context, Result};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::error;

/// rhypedb's loopback native-TCP wire port inside the guest (see `start_database`).
pub(crate) const RHYPEDB_TCP_PORT: u16 = 4201;

/// In-VM ceiling on concurrent app→DB leg connections (both planes share it). Bounds the fd/task
/// footprint a tenant hammering its OWN loopback proxy can create — self-DoS of its own VM only
/// (the host gateway independently caps the DB-VM-facing relays), but cheap to bound.
pub(crate) const DB_LEG_MAX_CONNS: usize = 512;

/// P2 §7.6 — one in-guest loopback proxy listener for the app→DB leg. Binds
/// `127.0.0.1:local_port` (a rhypedb port the tenant's client already targets on a co-located
/// project) and, per accepted connection, dials the host DB gateway (`172.16.0.1:gateway_port`)
/// and byte-transparently splices. The gateway authenticates by our UNFORGEABLE source IP (the L2
/// source-guard pins {ip,mac}↔TAP) and forwards to the sibling DB VM. Best-effort: a bind failure
/// logs and disables that plane rather than crashing the agent; a per-connection dial failure
/// drops only that connection. Runs ONLY on a dedicated app VM, where these ports are free (no
/// co-located rhypedb). `permits` bounds concurrent connections across both planes.
pub(crate) async fn db_leg_loopback_proxy(
    local_port: u16,
    gateway_port: u16,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
) {
    use tokio::io::copy_bidirectional;
    let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, port = local_port, "app→DB leg: failed to bind loopback proxy");
            return;
        }
    };
    loop {
        let (mut local, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Back off briefly so a transient accept errno can't busy-spin the loop.
                error!(error = %e, port = local_port, "app→DB leg: accept error");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        // Bound concurrent leg connections (self-DoS guard). At the cap, drop this connection.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit; // released when this connection's splice ends
            let _ = local.set_nodelay(true);
            let mut up = match tokio::net::TcpStream::connect((
                jkbase_common::config::DB_GATEWAY_IP,
                gateway_port,
            ))
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, gateway_port, "app→DB leg: dial host DB gateway failed");
                    return;
                }
            };
            let _ = up.set_nodelay(true);
            // Byte-transparent full-duplex splice. Propagates half-close; the DB wire has
            // server-initiated pushes (subscriptions), so this must NOT assume request/response.
            let _ = copy_bidirectional(&mut local, &mut up).await;
        });
    }
}

/// Map a HOST-set `x-jkbase-db-port` header VALUE to the rhypedb loopback port to splice to:
/// exactly `"4200"`/`"4201"` ⇒ that port, anything else ⇒ `None` so the splice fails closed rather
/// than being aimed at an arbitrary in-guest port. Absent-header handling (default to the native
/// wire `4201`, the external edge's behavior) is at the CALL site, so a header that is present but
/// unparseable/unknown can never silently default — it returns `None` → 400. The header is never
/// guest-controlled (see the caller).
fn db_splice_target_port(value: &str) -> Option<u16> {
    if value == RHYPEDB_TCP_PORT.to_string() {
        Some(RHYPEDB_TCP_PORT)
    } else if value == RHYPEDB_HTTP_PORT.to_string() {
        Some(RHYPEDB_HTTP_PORT)
    } else {
        None
    }
}

/// Constant-time byte compare for the splice-secret check (the agent has no other
/// const-time primitive; mirrors the edge/control-plane discipline).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// [R3] The managed-DB reach-plane backend leg. The edge does an HTTP/1.1 `Upgrade` to
/// `/_jkbase/db` presenting the per-deploy splice secret; on `101` the agent splices the
/// raw byte stream to rhypedb's loopback TCP wire (`127.0.0.1:4201`). The DB stays
/// loopback-only — this is the sole in-VM path to it, gated on the secret so one isolation
/// slip (a sibling reaching this eth0 port) isn't a direct splice into the unauthenticated
/// engine. Not an HTTP backend, so there is NO hyper handshake on the backend leg.
/// Verify the host→agent reach-plane secret ([R3]/[RB2]). No secret configured (no managed DB
/// / not baked) OR a mismatch ⇒ false, so every gated endpoint fails closed to 404 (never
/// confirming the endpoint or the DB's existence). Constant-time compare.
fn db_secret_ok(state: &AgentState, req: &Request<hyper::body::Incoming>) -> bool {
    let Some(expected) = state.db_splice_secret.as_deref() else {
        return false;
    };
    let presented = req
        .headers()
        .get("x-jkbase-db-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ct_eq(presented.as_bytes(), expected.as_bytes())
}

pub(crate) async fn handle_db_splice(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    // Verify the host→agent secret. No secret / mismatch ⇒ 404, fail-closed.
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }

    // Which loopback DB port to splice to. The header is HOST-set (the external edge omits it →
    // the native wire; the app→DB host gateway sets it per leg), NEVER guest-controlled: an
    // external client only owns the raw bytes AFTER the 101, not this upgrade request's headers.
    // Fail closed on any value other than the two known rhypedb ports so this can never be aimed
    // at an arbitrary in-guest port. Absent ⇒ 4201 (the native wire), preserving the edge path.
    let target_port = match req.headers().get("x-jkbase-db-port") {
        None => RHYPEDB_TCP_PORT, // absent → native wire (external edge default, unchanged)
        Some(v) => match v.to_str().ok().and_then(db_splice_target_port) {
            Some(p) => p,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("bad db port")))
                    .unwrap();
            }
        },
    };

    // Require a real upgrade so a valid-secret non-upgrade request can't leak a permit on
    // an `on()` future that never resolves.
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }

    // Bound concurrent splices with the same intra-VM permit pool as WS upgrades.
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };

    // Connect the raw loopback wire BEFORE returning 101 (a connect failure must not leave
    // the edge spliced to nothing).
    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, port = target_port, "db splice: rhypedb loopback wire not available");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("db not available")))
                .unwrap();
        }
    };
    let _ = jkbase_wsproxy::set_relay_keepalive(&backend);

    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let _permit = permit; // released when the relay ends
        match client_upgrade.await {
            Ok(upgraded) => {
                jkbase_wsproxy::relay_bidirectional(
                    TokioIo::new(upgraded),
                    backend,
                    jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT,
                )
                .await;
            }
            Err(e) => error!(error = %e, "db splice: client upgrade failed"),
        }
    });

    // 101 → the edge splices its (TLS) side to this upgraded stream.
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// rhypedb's loopback HTTP admin port inside the guest (see `db_manifest`).
pub(crate) const RHYPEDB_HTTP_PORT: u16 = 4200;

/// A console DB tools op → the target route on rhypedb's OPEN loopback HTTP plane. The rhypedb
/// path is HARD-CODED per variant (never derived from the host request), so `/admin/*` — which
/// would need the admin token anyway — is unreachable through this seam.
#[derive(Clone, Copy)]
pub(crate) enum DbHttpOp {
    Query,
    Schema,
    Status,
}

impl DbHttpOp {
    fn method(self) -> &'static str {
        match self {
            DbHttpOp::Query => "POST",
            DbHttpOp::Schema | DbHttpOp::Status => "GET",
        }
    }
    fn rhypedb_path(self) -> &'static str {
        match self {
            DbHttpOp::Query => "/query",
            DbHttpOp::Schema => "/schema",
            DbHttpOp::Status => "/status",
        }
    }
    fn forwards_body(self) -> bool {
        matches!(self, DbHttpOp::Query)
    }
}

/// Max inbound query body the agent accepts before forwarding to the engine.
const MAX_DB_QUERY_IN_BYTES: usize = 256 * 1024;
/// Max engine response the agent buffers before relaying to the host (result rows are
/// governor-bounded engine-side; this caps a pathological payload).
const MAX_DB_QUERY_OUT_BYTES: usize = 16 * 1024 * 1024;

/// Console DB proxy ([managed-rhypedb studio]). Forward a secret-gated host request to rhypedb's
/// OPEN loopback HTTP plane (`/query` | `/schema` | `/status`; NEVER `/admin/*`) and relay the
/// engine's status + JSON body back. Bounded in + out; concurrency-capped by the shared upgrade
/// permit pool. Lets the console query/introspect the DB without ever exposing it off-loopback.
pub(crate) async fn handle_db_query(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
    op: DbHttpOp,
) -> Response<Full<Bytes>> {
    use http_body_util::Limited;
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    let Ok(_permit) = upgrade_permits().clone().try_acquire_owned() else {
        return too_many_db_connections();
    };

    // Read the (bounded) inbound body only for the write/query op; schema/status are GET.
    let body = if op.forwards_body() {
        match Limited::new(req.into_body(), MAX_DB_QUERY_IN_BYTES)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from("query too large")))
                    .unwrap();
            }
        }
    } else {
        Bytes::new()
    };

    match engine_request(
        ENGINE_HTTP,
        op.method(),
        op.rhypedb_path(),
        None,
        body,
        MAX_DB_QUERY_OUT_BYTES,
        "db query",
    )
    .await
    {
        Ok((status, out)) => json_response(status, out),
        Err(resp) => resp,
    }
}

/// Max engine response to a `rewrite-covers` pass (a handful of counters — anything bigger is not
/// the engine's answer).
const MAX_DB_ADMIN_OUT_BYTES: usize = 64 * 1024;

/// Owner-driven `rewrite-covers` pass ([RB1] admin plane). The host POSTs `/_jkbase/db/rewrite-covers`
/// presenting the splice secret; the agent authorizes rhypedb's loopback
/// `POST /admin/rewrite-covers` with the in-guest admin token and relays the engine's JSON stats
/// (`ok`, `objects`, `rev_edges_rewritten`, `index_entries_rewritten`, `cover_peers_sound`).
///
/// The engine path is HARD-CODED and no inbound body or header is forwarded, so this seam reaches
/// exactly one admin route — never a host- or console-chosen one — and the admin token never
/// leaves the guest. The pass runs in engine-side batches and is safe to interrupt and rerun, so
/// the host bounds it with a deadline and simply drops the connection on expiry (the engine
/// finishes or stops on its own; a rerun redoes only what is still stale). POST-only so a stray GET
/// can never start a mutating pass. Holds one upgrade permit for the pass's lifetime.
pub(crate) async fn handle_db_rewrite_covers(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    // No admin token baked ⇒ no managed DB (or one deployed before the admin plane existed):
    // fail closed exactly like an unknown endpoint.
    let Some(admin_token) = state.db_admin_token.clone() else {
        return not_found_response();
    };
    if req.method() != hyper::Method::POST {
        return Response::builder()
            .status(StatusCode::METHOD_NOT_ALLOWED)
            .header("allow", "POST")
            .body(Full::new(Bytes::new()))
            .unwrap();
    }
    let Ok(_permit) = upgrade_permits().clone().try_acquire_owned() else {
        return too_many_db_connections();
    };
    drop(req); // nothing from the host request reaches the engine
    match engine_request(
        ENGINE_HTTP,
        "POST",
        "/admin/rewrite-covers",
        Some(&admin_token),
        Bytes::new(),
        MAX_DB_ADMIN_OUT_BYTES,
        "db rewrite-covers",
    )
    .await
    {
        Ok((status, out)) => json_response(status, out),
        Err(resp) => resp,
    }
}

/// rhypedb's loopback HTTP plane, the only engine address the host-facing handlers dial.
const ENGINE_HTTP: SocketAddr = SocketAddr::new(
    std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
    RHYPEDB_HTTP_PORT,
);

/// One request to rhypedb's loopback HTTP plane (`engine`: always [`ENGINE_HTTP`] outside tests): send `method path`
/// (with `Authorization: Bearer <admin>` only when `admin_bearer` is set), and read the response
/// body bounded by `out_cap`. `Err` is the ready-made 502 for the host (engine down / handshake /
/// send failure / oversized body); `label` names the op in the guest log.
async fn engine_request(
    engine: SocketAddr,
    method: &str,
    path: &'static str,
    admin_bearer: Option<&str>,
    body: Bytes,
    out_cap: usize,
    label: &'static str,
) -> std::result::Result<(StatusCode, Bytes), Response<Full<Bytes>>> {
    use http_body_util::Limited;
    let backend = match tokio::net::TcpStream::connect(engine).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, op = label, "rhypedb loopback http not available");
            return Err(bad_gateway("db not available"));
        }
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(backend)).await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, op = label, "loopback handshake failed");
                return Err(bad_gateway("db handshake failed"));
            }
        };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let mut rreq = Request::builder()
        .method(method)
        .uri(path)
        .header("host", "127.0.0.1")
        .header("content-type", "application/json");
    if let Some(token) = admin_bearer {
        rreq = rreq.header("authorization", format!("Bearer {token}"));
    }
    let resp = match sender
        .send_request(rreq.body(Full::new(body)).unwrap())
        .await
    {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, op = label, "engine request failed");
            return Err(bad_gateway("db request failed"));
        }
    };
    let status = resp.status();
    match Limited::new(resp.into_body(), out_cap).collect().await {
        Ok(c) => Ok((status, c.to_bytes())),
        Err(_) => Err(bad_gateway("db response too large")),
    }
}

fn json_response(status: StatusCode, body: Bytes) -> Response<Full<Bytes>> {
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap()
}

fn too_many_db_connections() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("retry-after", "5")
        .body(Full::new(Bytes::from("too many concurrent db connections")))
        .unwrap()
}

/// Hard cap on a restore tar the host may push ([RB3]) — defense-in-depth so even a
/// host-authenticated push can't fill the data disk unbounded. The disk itself is the real
/// bound; this fails fast well before an accidental runaway.
const MAX_RESTORE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// [RB2]/[RB3] Managed-DB backup PULL. The host does an HTTP/1.1 `Upgrade` to
/// `/_jkbase/db/backup` presenting the splice secret; the agent authorizes the loopback
/// `GET /admin/backup/stream` with the reserved admin token ([RB1]) and streams the tar back
/// over the upgraded socket, DE-CHUNKED and never buffered ([RB3]). The host validates the tar
/// end-of-archive marker before committing the object ([RB8]); a truncated relay = a failed
/// backup. The admin token never leaves the guest — only the opaque tar bytes do.
pub(crate) async fn handle_db_backup(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    use tokio::io::AsyncWriteExt;
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    // Need the reserved admin token to authorize the loopback admin call; absent ⇒ 404
    // (no managed DB / not baked), fail-closed.
    let Some(admin_token) = state.db_admin_token.clone() else {
        return not_found_response();
    };
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };

    // Connect + send the admin request BEFORE returning 101, so a DB-down / auth failure is a
    // clean non-101 error to the host rather than an empty upgraded stream.
    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_HTTP_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "db backup: rhypedb loopback http not available");
            return bad_gateway("db not available");
        }
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(backend)).await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "db backup: loopback handshake failed");
                return bad_gateway("db handshake failed");
            }
        };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let admin_req = Request::builder()
        .method("GET")
        .uri("/admin/backup/stream")
        .header("host", "127.0.0.1")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = match sender.send_request(admin_req).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "db backup: admin request failed");
            return bad_gateway("db backup request failed");
        }
    };
    if resp.status() != StatusCode::OK {
        error!(status = %resp.status(), "db backup: admin returned non-200");
        return bad_gateway("db backup unavailable");
    }

    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let _permit = permit; // released when the relay ends
        // Keep the loopback connection driver alive by moving `sender` in (dropping it early
        // could cancel the in-flight response body).
        let _sender = sender;
        match client_upgrade.await {
            Ok(upgraded) => {
                let mut out = TokioIo::new(upgraded);
                let mut body = resp.into_body();
                let mut clean = true;
                loop {
                    match body.frame().await {
                        Some(Ok(frame)) => {
                            if let Some(chunk) = frame.data_ref()
                                && out.write_all(chunk).await.is_err()
                            {
                                clean = false;
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!(error = %e, "db backup: body stream error");
                            clean = false;
                            break;
                        }
                        None => break,
                    }
                }
                // Half-close so the host sees a clean EOF = end of the tar. A mid-stream error
                // truncates the body → the host's tar-EOF validation rejects it ([RB8]).
                let _ = out.shutdown().await;
                if !clean {
                    tracing::warn!(
                        "db backup: tar stream ended early (host will reject as truncated)"
                    );
                }
            }
            Err(e) => error!(error = %e, "db backup: client upgrade failed"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db-backup")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// [RB2]/[RB3]/[RB5] Managed-DB restore PUSH. The host Upgrades to `/_jkbase/db/restore`
/// (splice-secret gated) and streams a backup tar; the agent untars it IN-GUEST (the host
/// never writes the data-disk FS — [RB5]), atomically stages a complete snapshot, respawns
/// rhypedb with `RHYPEDB_RESTORE_FROM`, waits for it to serve again, then reports `ok` /
/// `err: …` back over the socket so the host records the outcome.
pub(crate) async fn handle_db_restore(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    if !Path::new("/mnt/data").exists() {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from("no data disk")))
            .unwrap();
    }
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };
    let admin_token = state.db_admin_token.clone();
    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _permit = permit;
        let upgraded = match client_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                error!(error = %e, "db restore: client upgrade failed");
                return;
            }
        };
        let mut io = TokioIo::new(upgraded);
        let result = perform_restore(&state.containers, admin_token.as_deref(), &mut io).await;
        let line = match &result {
            Ok(()) => "ok\n".to_string(),
            Err(e) => {
                error!(error = %e, "db restore failed");
                format!("err: {e}\n")
            }
        };
        let _ = io.write_all(line.as_bytes()).await;
        let _ = io.shutdown().await;
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db-restore")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Drive one restore: stream the tar off `io` to a temp file (bounded, never in RAM), untar
/// it traversal-safe into a fresh staging dir, require a complete snapshot (its
/// `MANIFEST.json`), atomically publish it, then respawn rhypedb to restore-on-boot and wait
/// for it to serve. On success clears the staging + resets the DB manifest ([RB9]).
async fn perform_restore<S>(
    containers: &Arc<ContainerSupervisor>,
    admin_token: Option<&str>,
    io: &mut S,
) -> Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let base = PathBuf::from("/mnt/data/volumes/rhypedb-restore");
    let incoming = base.join(".incoming");
    let snapshot = base.join("snapshot");
    let tar_path = base.join(".incoming.tar");
    std::fs::create_dir_all(&base).context("create restore volume dir")?;
    let _ = std::fs::remove_dir_all(&incoming);
    let _ = std::fs::remove_file(&tar_path);

    // Stream the pushed tar → temp file on the data disk (bounded by MAX_RESTORE_BYTES; the
    // host half-closes after the archive, so read-to-EOF yields the whole tar).
    {
        let mut f = tokio::fs::File::create(&tar_path)
            .await
            .context("create restore tar")?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = io.read(&mut buf).await.context("read restore stream")?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_RESTORE_BYTES {
                let _ = tokio::fs::remove_file(&tar_path).await;
                anyhow::bail!("restore stream exceeds {MAX_RESTORE_BYTES} bytes");
            }
            tokio::io::AsyncWriteExt::write_all(&mut f, &buf[..n])
                .await
                .context("write restore tar")?;
        }
        tokio::io::AsyncWriteExt::flush(&mut f)
            .await
            .context("flush restore tar")?;
    }

    // Untar traversal-safe (the `tar` crate refuses `..`/absolute escapes) on the blocking
    // pool. Then require a complete snapshot before publishing it.
    let incoming_c = incoming.clone();
    let tar_c = tar_path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&incoming_c)?;
        let f = std::fs::File::open(&tar_c)?;
        let mut ar = tar::Archive::new(f);
        ar.set_preserve_permissions(false);
        ar.unpack(&incoming_c).context("untar restore snapshot")?;
        Ok(())
    })
    .await
    .context("untar task join")??;
    let _ = std::fs::remove_file(&tar_path);
    // Require a COMPLETE snapshot (MANIFEST.json + every listed SST + wal.log + schema.rhype),
    // not just a MANIFEST.json — a stream truncated at a tar-entry boundary after MANIFEST but
    // before an SST unpacks cleanly yet is unrestorable. Publishing it would brick the DB boot
    // (rhypedb fail-closes, and db_manifest would re-arm the restore every boot). Refuse instead,
    // so the DB simply boots its pre-restore data.
    if !container_supervisor::snapshot_is_complete(&incoming) {
        let _ = std::fs::remove_dir_all(&incoming);
        anyhow::bail!("pushed archive is not a complete backup (truncated / missing files)");
    }

    // Atomically publish: only a complete snapshot ever becomes `snapshot/`, so a partial
    // untar can never trigger a restore that would brick the DB boot.
    let _ = std::fs::remove_dir_all(&snapshot);
    std::fs::rename(&incoming, &snapshot).context("publish restore snapshot")?;

    // Respawn the DB to restore-on-boot, then wait for it to serve again.
    containers.restore_database(admin_token).await?;
    if !wait_db_healthy(std::time::Duration::from_secs(300)).await {
        anyhow::bail!("managed DB did not become healthy after restore");
    }
    containers.finalize_restore(admin_token).await;
    Ok(())
}

/// Poll the loopback DB `/health` until it serves 200 (⟹ rhypedb finished restore-on-boot and
/// opened the database) or the deadline passes.
async fn wait_db_healthy(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if db_health_probe().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

async fn db_health_probe() -> bool {
    let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_HTTP_PORT)).await else {
        return false;
    };
    let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    else {
        return false;
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .header("host", "127.0.0.1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    matches!(sender.send_request(req).await, Ok(r) if r.status() == StatusCode::OK)
}

fn bad_gateway(msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::from(msg)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_splice_target_port_is_host_set_and_fail_closed() {
        // The two known rhypedb loopback ports the app→DB gateway may target.
        assert_eq!(db_splice_target_port("4201"), Some(RHYPEDB_TCP_PORT));
        assert_eq!(db_splice_target_port("4200"), Some(RHYPEDB_HTTP_PORT));
        // Anything else ⇒ None → the caller fails closed with 400; never aimable at an arbitrary
        // in-guest port. (Absent-header default-to-4201 is the call site's job, not this helper's,
        // so a present-but-unparseable/unknown value can't silently default.)
        assert_eq!(db_splice_target_port("22"), None);
        assert_eq!(db_splice_target_port("9090"), None);
        assert_eq!(db_splice_target_port(""), None);
        assert_eq!(db_splice_target_port("4201 "), None);
        assert_eq!(db_splice_target_port("04201"), None);
    }

    /// A fake engine on an ephemeral port: records each request's method, path, authorization
    /// and body, and answers `reply`.
    async fn fake_engine(
        reply: &'static str,
    ) -> (
        SocketAddr,
        tokio::sync::mpsc::UnboundedReceiver<(String, String, Option<String>, Bytes)>,
    ) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let tx = tx.clone();
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |req: Request<hyper::body::Incoming>| {
                            let tx = tx.clone();
                            async move {
                                let method = req.method().to_string();
                                let path = req.uri().path().to_string();
                                let auth = req
                                    .headers()
                                    .get("authorization")
                                    .map(|v| v.to_str().unwrap().to_string());
                                let body = req.into_body().collect().await.unwrap().to_bytes();
                                tx.send((method, path, auth, body)).unwrap();
                                Ok::<_, std::convert::Infallible>(Response::new(Full::new(
                                    Bytes::from(reply),
                                )))
                            }
                        });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .await;
                });
            }
        });
        (addr, rx)
    }

    /// The admin op reaches exactly `POST /admin/rewrite-covers` with the in-guest bearer and an
    /// empty body, and relays the engine's status + JSON.
    #[tokio::test]
    async fn rewrite_covers_engine_request_is_the_hard_coded_admin_call() {
        let (engine, mut seen) = fake_engine(r#"{"ok":true,"cover_peers_sound":true}"#).await;
        let (status, body) = engine_request(
            engine,
            "POST",
            "/admin/rewrite-covers",
            Some("adm-tok"),
            Bytes::new(),
            MAX_DB_ADMIN_OUT_BYTES,
            "test",
        )
        .await
        .unwrap();
        assert_eq!(status, StatusCode::OK);
        assert_eq!(&body[..], br#"{"ok":true,"cover_peers_sound":true}"#);
        let (method, path, auth, sent) = seen.recv().await.unwrap();
        assert_eq!(method, "POST");
        assert_eq!(path, "/admin/rewrite-covers");
        assert_eq!(auth.as_deref(), Some("Bearer adm-tok"));
        assert!(sent.is_empty());
    }

    /// The open-plane console ops never carry the admin bearer.
    #[tokio::test]
    async fn open_plane_engine_request_sends_no_bearer() {
        let (engine, mut seen) = fake_engine("{}").await;
        engine_request(engine, "GET", "/status", None, Bytes::new(), 1024, "test")
            .await
            .unwrap();
        let (_, path, auth, _) = seen.recv().await.unwrap();
        assert_eq!(path, "/status");
        assert_eq!(auth, None);
    }

    /// An engine answer over the cap is a 502, never a truncated relay.
    #[tokio::test]
    async fn engine_request_bounds_the_response() {
        let (engine, _seen) = fake_engine(r#"{"ok":true,"padding":"xxxxxxxxxxxxxxxx"}"#).await;
        let err = engine_request(
            engine,
            "POST",
            "/admin/rewrite-covers",
            Some("t"),
            Bytes::new(),
            8,
            "test",
        )
        .await
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }

    /// Nothing listening ⇒ a clean 502 (rhypedb down), not a hang or panic.
    #[tokio::test]
    async fn engine_request_engine_down_is_bad_gateway() {
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let err = engine_request(
            dead,
            "POST",
            "/admin/rewrite-covers",
            Some("t"),
            Bytes::new(),
            64,
            "test",
        )
        .await
        .unwrap_err();
        assert_eq!(err.status(), StatusCode::BAD_GATEWAY);
    }
}
