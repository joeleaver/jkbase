//! The host-driven ops on rhypedb's loopback HTTP plane: the console's open-plane query /
//! schema / status relay and the owner's admin `rewrite-covers` pass. Every engine path is
//! HARD-CODED per op (never taken from the host request), and the admin bearer is attached only
//! to the one admin route, so nothing here can aim the engine at a host- or tenant-chosen route.
//! The secret gate and permit pool are shared with the rest of the reach seam ([`crate::db_reach`]).

use crate::db_reach::{RHYPEDB_HTTP_PORT, bad_gateway, db_secret_ok, too_many_db_connections};
use crate::{AgentState, not_found_response, upgrade_permits};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tracing::{error, info};

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

/// Agent-side bound on one engine pass. The engine runs the pass in a blocking task that outlives
/// any dropped connection, so this is NOT what stops the pass — it only bounds how long a wedged
/// engine can hold [`REWRITE_RUNNING`] (and its upgrade permit). Longer than the host's own
/// deadline so a healthy-but-slow pass the host gave up on still releases the flag on its answer.
const REWRITE_PASS_MAX: Duration = Duration::from_secs(2 * 60 * 60);

/// One VM, one engine, one pass. Set while an engine `rewrite-covers` pass is in flight —
/// tracked HERE rather than on the host because the engine keeps working after the host's
/// connection drops (Ctrl-C, host deadline, server restart): only the agent sees the pass end.
static REWRITE_RUNNING: AtomicBool = AtomicBool::new(false);

/// RAII claim on a single-flight flag; released on drop, i.e. when the engine has answered (or
/// [`REWRITE_PASS_MAX`] expired), never merely because the host hung up.
struct PassClaim(&'static AtomicBool);

impl PassClaim {
    fn try_take(flag: &'static AtomicBool) -> Option<Self> {
        flag.compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| PassClaim(flag))
    }
}

impl Drop for PassClaim {
    fn drop(&mut self) {
        self.0.store(false, Ordering::Release);
    }
}

/// Owner-driven `rewrite-covers` pass ([RB1] admin plane). The host POSTs `/_jkbase/db/rewrite-covers`
/// presenting the splice secret; the agent authorizes rhypedb's loopback
/// `POST /admin/rewrite-covers` with the in-guest admin token and relays the engine's JSON stats
/// (`ok`, `objects`, `rev_edges_rewritten`, `index_entries_rewritten`, `cover_peers_sound`).
///
/// The engine path is HARD-CODED and no inbound body or header is forwarded, so this seam reaches
/// exactly one admin route — never a host- or console-chosen one — and the admin token never
/// leaves the guest. POST-only so a stray GET can never start a mutating pass. Single-flight per
/// VM ([`REWRITE_RUNNING`]): a second call while a pass runs — including one whose host request
/// is long gone — is a 409, so reruns can't stack concurrent passes on the engine. (The one gap:
/// after [`REWRITE_PASS_MAX`] the claim is released even if a wedged engine is still working —
/// a deliberate bound, so a hung engine can't refuse the owner forever.)
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
    drop(req); // nothing from the host request reaches the engine
    run_rewrite_covers(ENGINE_HTTP, admin_token, &REWRITE_RUNNING).await
}

/// The single-flight engine call behind [`handle_db_rewrite_covers`] (`engine` / `running` are
/// parameters only so tests can use their own). The engine call runs in a DETACHED task that owns
/// the claim and the upgrade permit, so dropping this future (host hung up) leaves both held until
/// the engine actually answers — the flag mirrors the engine's real state, not the host's.
async fn run_rewrite_covers(
    engine: SocketAddr,
    admin_token: String,
    running: &'static AtomicBool,
) -> Response<Full<Bytes>> {
    let Some(claim) = PassClaim::try_take(running) else {
        return json_error(
            StatusCode::CONFLICT,
            "a rewrite-covers pass is already running on this database; wait for it to finish \
             (rerunning afterwards is safe)",
        );
    };
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return too_many_db_connections();
    };
    let (tx, rx) = tokio::sync::oneshot::channel();
    tokio::spawn(async move {
        let (_claim, _permit) = (claim, permit);
        let call = engine_request(
            engine,
            "POST",
            "/admin/rewrite-covers",
            Some(&admin_token),
            Bytes::new(),
            MAX_DB_ADMIN_OUT_BYTES,
            "db rewrite-covers",
        );
        let resp = match tokio::time::timeout(REWRITE_PASS_MAX, call).await {
            // An engine that predates the route answers 404; say so distinctly, so the host's own
            // 404 handling ("this agent has no such endpoint") never misattributes it.
            Ok(Ok((StatusCode::NOT_FOUND, _))) => json_error(
                StatusCode::NOT_IMPLEMENTED,
                "this database engine predates rewrite-covers; redeploy the project to pick up \
                 the current engine",
            ),
            Ok(Ok((status, out))) => json_response(status, out),
            Ok(Err(resp)) => resp,
            Err(_) => {
                error!("db rewrite-covers: engine gave no answer within the agent's bound");
                json_error(
                    StatusCode::GATEWAY_TIMEOUT,
                    "the database did not answer the rewrite-covers pass in time",
                )
            }
        };
        info!(status = %resp.status(), "db rewrite-covers pass ended");
        // The host may have hung up; the claim is released here regardless.
        let _ = tx.send(resp);
    });
    rx.await
        .unwrap_or_else(|_| bad_gateway("db rewrite-covers task failed"))
}

/// `{"ok":false,"error":msg}` — the engine's own failure shape, so the CLI reads one shape.
fn json_error(status: StatusCode, msg: &str) -> Response<Full<Bytes>> {
    let body = serde_json::json!({ "ok": false, "error": msg }).to_string();
    json_response(status, Bytes::from(body))
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

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::TcpListener;

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

    /// A fake engine whose every answer (`status`, `reply`) waits for `gate` — a pass that is
    /// still running until the test says it finished.
    async fn gated_engine(
        status: StatusCode,
        reply: &'static str,
        gate: Arc<tokio::sync::Semaphore>,
    ) -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let (tx, gate) = (tx.clone(), gate.clone());
                tokio::spawn(async move {
                    let svc =
                        hyper::service::service_fn(move |_req: Request<hyper::body::Incoming>| {
                            let (tx, gate) = (tx.clone(), gate.clone());
                            async move {
                                tx.send(()).unwrap();
                                gate.acquire().await.unwrap().forget();
                                let mut resp = Response::new(Full::new(Bytes::from(reply)));
                                *resp.status_mut() = status;
                                Ok::<_, std::convert::Infallible>(resp)
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

    async fn wait_released(flag: &AtomicBool) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while flag.load(Ordering::Acquire) {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("the claim was never released");
    }

    /// The engine keeps working after the host hangs up, so the agent's single-flight must too:
    /// a caller dropped mid-pass leaves the claim held (a rerun is a 409, nothing reaches the
    /// engine), and the claim is released only when the engine actually answers.
    #[tokio::test]
    async fn rewrite_covers_single_flight_outlives_a_dropped_caller() {
        static RUNNING: AtomicBool = AtomicBool::new(false);
        let gate = Arc::new(tokio::sync::Semaphore::new(0));
        let (engine, mut seen) = gated_engine(StatusCode::OK, r#"{"ok":true}"#, gate.clone()).await;

        let first = tokio::spawn(run_rewrite_covers(engine, "t".into(), &RUNNING));
        seen.recv().await.unwrap(); // the pass is running in the engine
        first.abort(); // the host hung up
        let _ = first.await;

        let second = run_rewrite_covers(engine, "t".into(), &RUNNING).await;
        assert_eq!(second.status(), StatusCode::CONFLICT);
        let body = second.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["ok"], false);
        assert!(v["error"].as_str().unwrap().contains("already running"));
        assert!(
            seen.try_recv().is_err(),
            "the refused rerun must never reach the engine"
        );

        gate.add_permits(1); // the engine finishes the orphaned pass
        wait_released(&RUNNING).await;
        gate.add_permits(1);
        let third = run_rewrite_covers(engine, "t".into(), &RUNNING).await;
        assert_eq!(third.status(), StatusCode::OK);
        assert!(!RUNNING.load(Ordering::Acquire));
    }

    /// An engine without the route (404) is reported as such — a distinct 501 — so the host's
    /// "older agent" reading of a bare 404 can never misattribute it; the claim is released.
    #[tokio::test]
    async fn rewrite_covers_engine_without_the_route_is_501() {
        static RUNNING: AtomicBool = AtomicBool::new(false);
        let gate = Arc::new(tokio::sync::Semaphore::new(1));
        let (engine, _seen) = gated_engine(StatusCode::NOT_FOUND, "not found", gate).await;
        let resp = run_rewrite_covers(engine, "t".into(), &RUNNING).await;
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
        let body = resp.into_body().collect().await.unwrap().to_bytes();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(v["error"].as_str().unwrap().contains("predates"));
        wait_released(&RUNNING).await;
    }

    /// Engine down ⇒ the claim is released with the 502, never left stuck.
    #[tokio::test]
    async fn rewrite_covers_engine_down_releases_the_claim() {
        static RUNNING: AtomicBool = AtomicBool::new(false);
        let l = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let dead = l.local_addr().unwrap();
        drop(l);
        let resp = run_rewrite_covers(dead, "t".into(), &RUNNING).await;
        assert_eq!(resp.status(), StatusCode::BAD_GATEWAY);
        wait_released(&RUNNING).await;
    }
}
