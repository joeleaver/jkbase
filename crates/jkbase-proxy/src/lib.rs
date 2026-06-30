pub mod db_preamble;
pub mod tls;

use anyhow::Result;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_util::sync::CancellationToken;
use tracing::{error, info};

/// Running backends: host-key → VM IP (fast path; only entries for live VMs).
pub type RoutingTable = Arc<RwLock<HashMap<String, String>>>;
pub type ActivityTracker = Arc<RwLock<HashMap<String, Instant>>>;
/// Why a wake didn't return a routable backend.
#[derive(Debug)]
pub enum WakeError {
    /// Project is over an enforced quota; do not retry until the period resets.
    /// Surfaced as HTTP 402 with no Retry-After.
    OverQuota(String),
    /// Transient (still starting up / restore in progress). Surfaced as 503.
    Unavailable(String),
    /// Registered, but it has no deployable content (artifacts gone) — it can never
    /// wake until the owner redeploys. Surfaced as 503 with a clear message and NO
    /// retry encouragement, so the proxy doesn't loop forever on "starting up".
    Gone(String),
}

pub type WakeCallback = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, WakeError>> + Send>> + Send + Sync,
>;

pub use jkbase_common::routing::DomainTarget;

/// All Active domains (running or hibernated): host-key → target. This is the
/// authority for "does this host exist + who owns it + which site", independent
/// of whether the VM is currently up. Maintained by the control plane.
pub type DomainMap = Arc<RwLock<HashMap<String, DomainTarget>>>;

/// Header the proxy uses to tell the agent which site to serve. Always stripped
/// from inbound requests and set only by the proxy, so it can't be spoofed.
pub const SITE_HEADER: &str = "x-jkbase-site";

pub fn new_routing_table() -> RoutingTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub fn new_domain_map() -> DomainMap {
    Arc::new(RwLock::new(HashMap::new()))
}

/// Unified proxy response body. A branch can return either a buffered `Full` (error
/// pages, small control responses) or a STREAMED backend body (object downloads,
/// large tenant responses) without buffering it in proxy memory — the latter is what
/// keeps a multi-GB object GET from sitting wholly in RAM.
type ProxyBody = BoxBody<Bytes, std::io::Error>;

/// Box a buffered body into [`ProxyBody`]. `Full`'s error is `Infallible`, mapped to
/// the `io::Error` the boxed type declares (the closure is never called).
fn full_body(b: impl Into<Bytes>) -> ProxyBody {
    Full::new(b.into())
        .map_err(|e: std::convert::Infallible| match e {})
        .boxed()
}

pub struct ProxyConfig {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub platform_domain: String,
    pub cert_manager: Option<Arc<tls::CertManager>>,
    pub api_addr: Option<String>,
    /// Local address of the tenant S3 object-store service. `storage.{domain}` is
    /// forwarded here (streamed). `None` disables the reserved host.
    pub storage_addr: Option<String>,
    pub domains: Option<DomainMap>,
    pub activity_tracker: Option<ActivityTracker>,
    pub wake_callback: Option<WakeCallback>,
    /// TCP port tenant backends listen on (default 80). Configurable so an
    /// integration test can point `forward_request` at a local echo server.
    pub backend_port: u16,
    /// Idle-reap window for a spliced upgrade (WebSocket &c.); see
    /// [`jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT`].
    pub relay_idle_timeout: Duration,
    /// Cap on concurrent in-flight relayed upgrades on this (shared) edge — bounds
    /// the fds + relay tasks a flood of cheap WebSocket holds can pin.
    pub max_concurrent_upgrades: usize,
    /// Pre-bound `:80` listener from systemd socket activation (zero-bounce Phase 2). `None` ⇒
    /// [`serve`] binds `0.0.0.0:http_port` itself (local-dev / non-activated path).
    pub http_listener: Option<TcpListener>,
    /// Pre-bound `:443` listener from systemd socket activation. `None` ⇒ bind `0.0.0.0:https_port`.
    pub https_listener: Option<TcpListener>,
}

struct SharedState {
    routes: RoutingTable,
    domain: Arc<String>,
    api_addr: Arc<Option<String>>,
    storage_addr: Arc<Option<String>>,
    domains: Option<DomainMap>,
    activity: Option<ActivityTracker>,
    wake_cb: Option<WakeCallback>,
    backend_port: u16,
    relay_idle_timeout: Duration,
    /// Permits for in-flight relayed upgrades; a relay holds one for its lifetime.
    relay_permits: Arc<tokio::sync::Semaphore>,
}

/// Serve the data-plane proxy until `shutdown` is cancelled, then GRACEFULLY DRAIN in-flight
/// connections before returning (zero-bounce Phase 2). On cancel each accept loop stops accepting
/// (the systemd-owned listening socket stays open for the successor) and every live connection is
/// `graceful_shutdown()`-ed; `serve` returns once the last connection task is gone. The caller
/// bounds the total wait (see the `DRAIN_GRACE` watchdog in jkbase-server) so a slow tenant can't
/// stall the successor's start.
pub async fn serve(
    config: ProxyConfig,
    routes: RoutingTable,
    shutdown: CancellationToken,
) -> Result<()> {
    let http_listener = config.http_listener;
    let https_listener = config.https_listener;
    let http_port = config.http_port;
    let shared = Arc::new(SharedState {
        routes,
        domain: Arc::new(config.platform_domain),
        api_addr: Arc::new(config.api_addr),
        storage_addr: Arc::new(config.storage_addr),
        domains: config.domains,
        activity: config.activity_tracker,
        wake_cb: config.wake_callback,
        backend_port: config.backend_port,
        relay_idle_timeout: config.relay_idle_timeout,
        relay_permits: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_upgrades)),
    });

    // Drain barrier: every live connection task holds a clone of `conn_tx`. Once all accept loops
    // break (on cancel) and every connection finishes, the last sender drops and `conn_rx.recv()`
    // returns `None` = fully drained. (`serve_http_redirect`'s instant 301/ACME conns are NOT in
    // the barrier — they only need to stop accepting.)
    let (conn_tx, mut conn_rx) = mpsc::channel::<()>(1);

    if let (Some(https_port), Some(cert_manager)) = (config.https_port, config.cert_manager.clone())
    {
        let acceptor = TlsAcceptor::from(cert_manager.server_config());
        cert_manager.spawn_reconcile();

        let shared_tls = shared.clone();
        let https_shutdown = shutdown.clone();
        let https_tx = conn_tx.clone();
        let https = tokio::spawn(async move {
            if let Err(e) = serve_https(
                https_listener,
                https_port,
                acceptor,
                shared_tls,
                https_shutdown,
                https_tx,
            )
            .await
            {
                error!(error = %e, "HTTPS proxy error");
            }
        });

        let res = serve_http_redirect(
            http_listener,
            http_port,
            shared.domain.clone(),
            cert_manager,
            shutdown.clone(),
        )
        .await;
        let _ = https.await; // its accept loop has broken on cancel
        res?;
    } else {
        serve_http(
            http_listener,
            http_port,
            shared,
            shutdown.clone(),
            conn_tx.clone(),
        )
        .await?;
    }

    // Wait for in-flight connections to finish draining (caller bounds this).
    drop(conn_tx);
    let _ = conn_rx.recv().await;
    Ok(())
}

/// Resolve the listener: the inherited (socket-activated) one if present, else bind `0.0.0.0:port`
/// — the exact historical `bind(([0,0,0,0],port))` semantics for the local-dev / non-activated path.
async fn resolve_listener(inherited: Option<TcpListener>, port: u16) -> Result<TcpListener> {
    match inherited {
        Some(l) => Ok(l),
        None => Ok(TcpListener::bind(SocketAddr::from(([0, 0, 0, 0], port))).await?),
    }
}

async fn serve_http(
    inherited: Option<TcpListener>,
    port: u16,
    shared: Arc<SharedState>,
    shutdown: CancellationToken,
    conn_tx: mpsc::Sender<()>,
) -> Result<()> {
    let listener = resolve_listener(inherited, port).await?;
    info!(addr = %listener.local_addr()?, domain = %shared.domain, "HTTP proxy listening");

    loop {
        let (stream, _peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break, // stop accepting → leave the socket for the successor
            accept = listener.accept() => match accept {
                Ok(v) => v,
                Err(e) => { error!(error = %e, "proxy accept error"); continue; }
            },
        };
        let shared = shared.clone();
        let shutdown = shutdown.clone();
        let permit = conn_tx.clone(); // held for the task's life = drain-barrier membership
        tokio::spawn(async move {
            let _permit = permit;
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy_request(shared.clone(), req));
            // with_upgrades(): keep driving the connection after a 101 so a proxied WebSocket can
            // reclaim the raw stream. header_read_timeout caps slow-header (slowloris) connections.
            let conn = http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(io, svc)
                .with_upgrades();
            drive_connection(conn, shutdown, "proxy connection error").await;
        });
    }
    Ok(()) // listener dropped → our DUP closes; systemd's original stays listening
}

async fn serve_https(
    inherited: Option<TcpListener>,
    port: u16,
    acceptor: TlsAcceptor,
    shared: Arc<SharedState>,
    shutdown: CancellationToken,
    conn_tx: mpsc::Sender<()>,
) -> Result<()> {
    let listener = resolve_listener(inherited, port).await?;
    info!(addr = %listener.local_addr()?, domain = %shared.domain, "HTTPS proxy listening");

    loop {
        let (stream, _peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break,
            accept = listener.accept() => match accept {
                Ok(v) => v,
                Err(e) => { error!(error = %e, "HTTPS accept error"); continue; }
            },
        };
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        let shutdown = shutdown.clone();
        let permit = conn_tx.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |req| proxy_request(shared.clone(), req));
            let conn = http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(io, svc)
                .with_upgrades();
            drive_connection(conn, shutdown, "HTTPS connection error").await;
        });
    }
    Ok(())
}

/// Drive one upgradeable hyper connection to completion, and on `shutdown` GRACEFULLY shut it down
/// (finish the in-flight response, send `Connection: close`, stop reading new requests) so the
/// drain barrier converges — `graceful_shutdown()` is what turns an idle keep-alive (whose later
/// reads are untimed) from "hangs until the client leaves" into "ends promptly". A WebSocket relay
/// has already handed off the raw stream at `101`, so this returns promptly and never pins the
/// drain on a long-lived splice.
async fn drive_connection<I, S>(
    conn: hyper::server::conn::http1::UpgradeableConnection<I, S>,
    shutdown: CancellationToken,
    err_msg: &'static str,
) where
    I: hyper::rt::Read + hyper::rt::Write + Unpin + Send + 'static,
    S: hyper::service::HttpService<hyper::body::Incoming> + Send + 'static,
    S::Future: Send,
    S::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    S::ResBody: Send + 'static,
    <S::ResBody as hyper::body::Body>::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
    <S::ResBody as hyper::body::Body>::Data: Send,
{
    tokio::pin!(conn);
    tokio::select! {
        res = conn.as_mut() => { if let Err(e) = res { error!(error = %e, "{err_msg}"); } }
        _ = shutdown.cancelled() => {
            conn.as_mut().graceful_shutdown();
            if let Err(e) = conn.await { error!(error = %e, "{err_msg}"); }
        }
    }
}

async fn serve_http_redirect(
    inherited: Option<TcpListener>,
    port: u16,
    domain: Arc<String>,
    cert_manager: Arc<tls::CertManager>,
    shutdown: CancellationToken,
) -> Result<()> {
    const ACME_PREFIX: &str = "/.well-known/acme-challenge/";
    let listener = resolve_listener(inherited, port).await?;
    info!(addr = %listener.local_addr()?, "HTTP->HTTPS redirect listening (with ACME HTTP-01)");

    loop {
        let (stream, _peer) = tokio::select! {
            biased;
            _ = shutdown.cancelled() => break, // stop accepting; 301/ACME conns are instant, no per-conn drain
            accept = listener.accept() => match accept {
                Ok(v) => v,
                Err(e) => { error!(error = %e, "redirect accept error"); continue; }
            },
        };
        let domain = domain.clone();
        let cm = cert_manager.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let domain = domain.clone();
                let cm = cm.clone();
                async move {
                    let path = req.uri().path().to_string();
                    // Answer ACME HTTP-01 challenges instead of redirecting them.
                    if let Some(token) = path.strip_prefix(ACME_PREFIX) {
                        return Ok::<_, hyper::Error>(match cm.challenge_response(token).await {
                            Some(body) => Response::builder()
                                .status(StatusCode::OK)
                                .header("Content-Type", "text/plain")
                                .body(Full::new(Bytes::from(body)))
                                .unwrap(),
                            None => Response::builder()
                                .status(StatusCode::NOT_FOUND)
                                .body(Full::new(Bytes::new()))
                                .unwrap(),
                        });
                    }
                    let host = req
                        .headers()
                        .get("host")
                        .and_then(|h| h.to_str().ok())
                        .unwrap_or(&domain)
                        .to_string();
                    let pq = req
                        .uri()
                        .path_and_query()
                        .map(|pq| pq.as_str())
                        .unwrap_or("/");
                    let location = format!("https://{host}{pq}");
                    Ok::<_, hyper::Error>(
                        Response::builder()
                            .status(StatusCode::MOVED_PERMANENTLY)
                            .header("Location", location)
                            .body(Full::new(Bytes::new()))
                            .unwrap(),
                    )
                }
            });
            if let Err(e) = http1::Builder::new()
                .timer(hyper_util::rt::TokioTimer::new())
                .header_read_timeout(Duration::from_secs(30))
                .serve_connection(io, svc)
                .await
            {
                error!(error = %e, "redirect connection error");
            }
        });
    }
    Ok(())
}

async fn proxy_request(
    shared: Arc<SharedState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let hostname = host.split(':').next().unwrap_or("");
    let subdomain = extract_subdomain(hostname, &shared.domain);

    // Route api.{domain} to the control plane (infra, never a tenant project).
    if subdomain.as_deref() == Some("api")
        && let Some(ref addr) = *shared.api_addr
    {
        return match forward_to_api(&shared, addr, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(error = %e, "API forward failed");
                Ok(bad_gateway())
            }
        };
    }

    // Route storage.{domain} to the tenant object-store service (infra host, never a
    // tenant project). Same local-forward pattern as the API; the service verifies
    // SigV4 against its configured public host, so the Host rewrite here is harmless.
    if subdomain.as_deref() == Some("storage")
        && let Some(ref addr) = *shared.storage_addr
    {
        return match forward_to_api(&shared, addr, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(error = %e, "object-store forward failed");
                Ok(bad_gateway())
            }
        };
    }

    // Host-key: bare apex/www both resolve to the "www" landing project.
    let host_key = match subdomain.as_deref() {
        None | Some("www") => "www".to_string(),
        Some(sub) => sub.to_string(),
    };

    // Resolve owner + site from the domain registry. A miss means the host is
    // not claimed by anyone → 404 (this replaces the old known_projects check).
    let target = if let Some(ref domains) = shared.domains {
        domains.read().await.get(&host_key).cloned()
    } else {
        None
    };
    let Some(target) = target else {
        return Ok(not_found(&host_key));
    };
    let project_id = target.project_id;
    let site = target.site.as_deref();

    // Record activity per project (the VM), not per host.
    if let Some(ref tracker) = shared.activity {
        let mut t = tracker.write().await;
        t.insert(project_id.clone(), Instant::now());
    }

    // Fast path: VM running. Routes are keyed by host-key too.
    let backend_ip = {
        let table = shared.routes.read().await;
        table.get(&host_key).cloned()
    };

    if let Some(ip) = backend_ip {
        return match forward_request(&shared, &ip, site, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(project = %project_id, error = %e, "backend request failed");
                Ok(bad_gateway())
            }
        };
    }

    // Known but not running — wake the owning project, then forward.
    let Some(ref cb) = shared.wake_cb else {
        return Ok(not_found(&host_key));
    };

    info!(project = %project_id, host = %host_key, "waking hibernated project");
    match (cb)(project_id.clone()).await {
        Ok(ip) => match forward_request(&shared, &ip, site, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(project = %project_id, error = %e, "backend failed after wake");
                Ok(bad_gateway())
            }
        },
        Err(WakeError::OverQuota(reason)) => {
            info!(project = %project_id, %reason, "refusing wake: over quota");
            Ok(payment_required(&reason))
        }
        Err(WakeError::Unavailable(e)) => {
            error!(project = %project_id, error = %e, "failed to wake project");
            Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "text/plain")
                .header("Retry-After", "5")
                .body(full_body("project is starting up, please retry"))
                .unwrap())
        }
        Err(WakeError::Gone(reason)) => {
            // No deployable content — don't pretend it's "starting up" (it never will
            // be) and don't send a short Retry-After that makes clients hammer.
            info!(project = %project_id, %reason, "refusing wake: project has no deployment");
            Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "text/plain")
                .body(full_body(
                    "This project has no active deployment. Redeploy it to bring it back online.",
                ))
                .unwrap())
        }
    }
}

fn payment_required(reason: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::PAYMENT_REQUIRED)
        .header("Content-Type", "text/plain")
        .body(full_body(format!("project over quota: {reason}")))
        .unwrap()
}

fn bad_gateway() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .body(full_body("bad gateway"))
        .unwrap()
}

fn not_found(project_id: &str) -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/plain")
        .body(full_body(format!("project not found: '{project_id}'")))
        .unwrap()
}

/// Drive the backend client connection. When the request may upgrade, the
/// connection future must run `with_upgrades()` so the raw stream can be
/// reclaimed from the 101 response; otherwise the plain future is fine.
fn spawn_backend_conn<B>(
    conn: hyper::client::conn::http1::Connection<TokioIo<tokio::net::TcpStream>, B>,
    upgrade: bool,
) where
    B: hyper::body::Body + Send + 'static,
    B::Data: Send,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    if upgrade {
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
    } else {
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }
}

/// A backend answered `101 Switching Protocols`. Splice the two upgraded byte
/// streams together (via [`jkbase_wsproxy::spawn_upgrade_relay`], which bounds
/// concurrency with `relay_permits` and reaps an idle relay after
/// `relay_idle_timeout`) and return the 101 — with its headers sanitized — so hyper
/// finishes the client-side switch (only because the listener runs
/// `serve_connection(...).with_upgrades()`).
///
/// `client_upgrade` is the `OnUpgrade` captured from the inbound request BEFORE its
/// body was moved into the backend request. A backend `101` with no client upgrade
/// becomes `502`; a relay refused by the cap becomes `503`.
fn relay_upgrade(
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    mut backend_resp: Response<hyper::body::Incoming>,
    shared: &SharedState,
    strip_hsts: bool,
) -> Response<ProxyBody> {
    use jkbase_wsproxy::UpgradeOutcome;
    match jkbase_wsproxy::spawn_upgrade_relay(
        client_upgrade,
        &mut backend_resp,
        shared.relay_idle_timeout,
        &shared.relay_permits,
    ) {
        UpgradeOutcome::Relayed => {}
        UpgradeOutcome::Unsolicited => {
            error!("backend sent 101 without a client upgrade request");
            return bad_gateway();
        }
        UpgradeOutcome::CapReached => {
            error!("in-flight upgrade cap reached; refusing relay");
            return upgrades_overloaded();
        }
    }

    let mut headers = backend_resp.headers().clone();
    // Preserve Connection+Upgrade (they carry the switch); strip the rest.
    jkbase_wsproxy::sanitize_response_headers(&mut headers, &shared.domain, strip_hsts, true);
    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    builder.body(full_body(Bytes::new())).unwrap()
}

/// 503 for an upgrade refused because the shared edge's in-flight-upgrade cap is full.
fn upgrades_overloaded() -> Response<ProxyBody> {
    Response::builder()
        .status(StatusCode::SERVICE_UNAVAILABLE)
        .header("Content-Type", "text/plain")
        .header("Retry-After", "5")
        .body(full_body("too many concurrent upgrades, please retry"))
        .unwrap()
}

async fn forward_to_api(
    shared: &SharedState,
    api_addr: &str,
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{api_addr}{path}");

    let upgrade = jkbase_wsproxy::is_upgrade_request(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = tokio::net::TcpStream::connect(api_addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    spawn_backend_conn(conn, upgrade);

    let mut builder = Request::builder().method(req.method()).uri(&uri);
    for (key, value) in req.headers() {
        // Strip host and the trusted internal site header (anti-spoof).
        if key != "host" && key.as_str().to_ascii_lowercase() != SITE_HEADER {
            builder = builder.header(key, value);
        }
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    let resp = sender.send_request(proxy_req).await?;
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Infra hosts (api/storage): keep their HSTS (`strip_hsts = false`).
        return Ok(relay_upgrade(client_upgrade, resp, shared, false));
    }
    let status = resp.status();
    let mut headers = resp.headers().clone();
    // Drop hop-by-hop + any apex-scoped Set-Cookie even for infra: the platform's own
    // session cookie must never be apex-scoped (it would leak to every tenant). HSTS
    // is kept — the console/API legitimately set their transport policy.
    jkbase_wsproxy::sanitize_response_headers(&mut headers, &shared.domain, false, false);
    // Stream the backend body through instead of buffering it in proxy RAM — an
    // object download (or any large tenant response) must not sit wholly in memory.
    let body = resp.into_body().map_err(std::io::Error::other).boxed();

    let mut builder = Response::builder().status(status);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    Ok(builder.body(body).unwrap())
}

async fn forward_request(
    shared: &SharedState,
    backend_ip: &str,
    site: Option<&str>,
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>> {
    let port = shared.backend_port;
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{backend_ip}:{port}{path_and_query}");

    // Capture the client-side upgrade future before the body is consumed below.
    let upgrade = jkbase_wsproxy::is_upgrade_request(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = tokio::net::TcpStream::connect(format!("{backend_ip}:{port}")).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    spawn_backend_conn(conn, upgrade);

    let mut builder = Request::builder().method(req.method()).uri(&uri);
    for (key, value) in req.headers() {
        // Drop any inbound site header so a client can't pick the served site;
        // the proxy is the sole authority for it.
        if key.as_str().to_ascii_lowercase() != SITE_HEADER {
            builder = builder.header(key, value);
        }
    }
    if let Some(site) = site {
        builder = builder.header(SITE_HEADER, site);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    let resp = sender.send_request(proxy_req).await?;
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Tenant backend (untrusted): strip HSTS too — the platform owns transport
        // policy for `*.{domain}`.
        return Ok(relay_upgrade(client_upgrade, resp, shared, true));
    }
    let status = resp.status();
    let mut headers = resp.headers().clone();
    jkbase_wsproxy::sanitize_response_headers(&mut headers, &shared.domain, true, false);
    // Stream the backend body through instead of buffering it in proxy RAM — an
    // object download (or any large tenant response) must not sit wholly in memory.
    let body = resp.into_body().map_err(std::io::Error::other).boxed();

    let mut builder = Response::builder().status(status);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    Ok(builder.body(body).unwrap())
}

fn extract_subdomain(hostname: &str, platform_domain: &str) -> Option<String> {
    let suffix = format!(".{platform_domain}");
    if let Some(subdomain) = hostname.strip_suffix(&suffix) {
        Some(subdomain.to_string())
    } else if hostname == platform_domain {
        None
    } else {
        Some(hostname.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_extraction() {
        assert_eq!(
            extract_subdomain("my-app.jkbase.app", "jkbase.app"),
            Some("my-app".to_string())
        );
        assert_eq!(
            extract_subdomain("api.jkbase.app", "jkbase.app"),
            Some("api".to_string())
        );
        assert_eq!(extract_subdomain("jkbase.app", "jkbase.app"), None);
        assert_eq!(
            extract_subdomain("console.jkbase.app", "jkbase.app"),
            Some("console".to_string())
        );
        assert_eq!(
            extract_subdomain("custom.example.com", "jkbase.app"),
            Some("custom.example.com".to_string())
        );
    }

    // (is_upgrade_request + header sanitization are tested in `jkbase-wsproxy`.)

    // The apex and "www" both map to the "www" landing project's host-key.
    #[test]
    fn host_key_normalizes_apex_and_www() {
        let key = |h: &str| match extract_subdomain(h, "jkbase.app").as_deref() {
            None | Some("www") => "www".to_string(),
            Some(sub) => sub.to_string(),
        };
        assert_eq!(key("jkbase.app"), "www");
        assert_eq!(key("www.jkbase.app"), "www");
        assert_eq!(key("docs.jkbase.app"), "docs");
        assert_eq!(key("docs.example.com"), "docs.example.com");
    }
}
