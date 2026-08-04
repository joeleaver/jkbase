pub mod db_ingress;
pub mod db_preamble;
pub mod db_relay;
pub mod l4_egress;
pub mod l4_ingress;
pub mod l4_plane;
pub mod tls;

use anyhow::Result;
use http_body_util::{BodyExt, Full, combinators::BoxBody};
use hyper::body::{Body, Bytes, Frame, SizeHint};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
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
    /// Throttled — the per-project `WAKE_BACKOFF` or the L4 plane's rate/budget cap refused
    /// this wake (distinct from a transient failure). Surfaced like [`WakeError::Unavailable`]
    /// at the HTTP/DB edge (503 + `Retry-After`); the L4 UDP responder drops silently.
    RateLimited(String),
}

pub type WakeCallback = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, WakeError>> + Send>> + Send + Sync,
>;

/// A successful managed-DB reach-plane authentication: the AUTHORITATIVE project (from
/// the key, not SNI — [R1]) and the host→agent splice secret to present on the backend
/// upgrade ([R3]).
pub struct DbAuthOk {
    pub project_id: String,
    pub splice_secret: String,
    /// The project's owning tenant (`None` for an ownerless project) — the dimension
    /// the per-tenant warm-VM quota is enforced on. Resolved server-side.
    pub tenant_id: Option<String>,
    /// The owner's effective per-tenant warm-VM cap (from the tenant-quota override
    /// or the platform default), resolved server-side at auth so the edge enforces it
    /// without a control-store dependency. Ignored when `tenant_id` is `None`.
    pub warm_vm_max: u32,
    /// The owner's effective per-tenant relay-COUNT cap (total live relays across all
    /// its projects), resolved server-side alongside `warm_vm_max`. Bounds the tenant's
    /// slice of the global relay pool. Ignored when `tenant_id` is `None`.
    pub warm_relay_max: u32,
}

/// Authenticate a DB reach preamble: `(akid, secret, claimed_project_from_sni)` →
/// `Some` iff the key resolves, its fingerprint matches, its project equals the SNI's
/// claimed project ([R1]), and the owner re-bind holds. Sync — the O(1) control-store
/// lookup and const-time fingerprint compare. Built by the server over the `Store`, so
/// `jkbase-proxy` needs no `jkbase-control` dependency (mirrors [`WakeCallback`]). The
/// TLS-exporter channel-binding ([R-replay]) is checked edge-side before this runs.
pub type DbAuthCallback = Arc<dyn Fn(&str, &str, &str) -> Option<DbAuthOk> + Send + Sync>;

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

/// A throttled activity-stamp closure over the shared [`ActivityTracker`] for `project_id`,
/// or `None` when no tracker is configured (integration tests). Mirrors the managed-DB reach
/// plane (`db_ingress::on_activity`): a spliced WebSocket or a long-lived streamed response
/// never re-enters [`proxy_request`] after its first request, so without a re-stamp the idle
/// loop would hibernate the VM out from under the live stream (wake-on-WS). The consumer
/// throttles to [`jkbase_wsproxy::ACTIVITY_STAMP_INTERVAL`], so the spawned map-write is cheap.
fn activity_stamp(
    activity: &Option<ActivityTracker>,
    project_id: &str,
) -> Option<Arc<dyn Fn() + Send + Sync>> {
    let act = activity.clone()?;
    let pid = project_id.to_string();
    Some(Arc::new(move || {
        let act = act.clone();
        let pid = pid.clone();
        tokio::spawn(async move {
            act.write().await.insert(pid, Instant::now());
        });
    }))
}

/// Wraps a STREAMED backend response body so that, once the stream OUTLIVES
/// [`jkbase_wsproxy::ACTIVITY_STAMP_INTERVAL`], each subsequent data frame re-stamps the
/// project's activity (again throttled to that interval). A long-lived streaming response
/// (Server-Sent Events, a chunked feed, a slow download) never re-enters [`proxy_request`]
/// after the opening request, so without this the idle loop would hibernate the VM out from
/// under the live stream (wake-on-WS, the SSE/streaming half).
///
/// `last` is SEEDED at construction, not left empty: the synchronous `proxy_request` stamp
/// already marks t=0, so a short/normal response — the overwhelmingly common case — completes
/// within the interval and adds NO extra stamp (no redundant spawn or tracker write on the hot
/// path). Only a stream still alive past the interval starts re-stamping. Only wraps tenant
/// responses (never infra api/storage/auth, which aren't hibernatable projects).
struct ActivityBody<B> {
    inner: B,
    stamp: Arc<dyn Fn() + Send + Sync>,
    /// Instant of the last stamp; seeded to construction time (≈ the `proxy_request` stamp) so
    /// the first re-stamp can only fire once the stream outlives `ACTIVITY_STAMP_INTERVAL`.
    last: Instant,
}

impl<B> ActivityBody<B> {
    fn new(inner: B, stamp: Arc<dyn Fn() + Send + Sync>) -> Self {
        Self {
            inner,
            stamp,
            last: Instant::now(),
        }
    }
}

impl<B> Body for ActivityBody<B>
where
    B: Body + Unpin,
{
    type Data = B::Data;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let res = Pin::new(&mut self.inner).poll_frame(cx);
        // Re-stamp only on a DATA frame (a trailers-only frame carries no traffic), and only
        // once per ACTIVITY_STAMP_INTERVAL so a chatty stream doesn't spawn a write per frame.
        if let Poll::Ready(Some(Ok(ref frame))) = res
            && frame.data_ref().is_some()
            && self.last.elapsed() >= jkbase_wsproxy::ACTIVITY_STAMP_INTERVAL
        {
            self.last = Instant::now();
            (self.stamp)();
        }
        res
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
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
    /// Local address of the jkbase-Auth issuer service (P3). `auth.{domain}` is forwarded
    /// here. `None` disables the reserved host. Same in-process-loopback model as `storage_addr`.
    pub auth_addr: Option<String>,
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
    /// Managed-DB reach-plane auth callback (server-built over the control store). `None`
    /// disables the DB ingress — a `jkbase-db`-ALPN connection is then dropped.
    pub db_auth_callback: Option<DbAuthCallback>,
    /// The live-relay registry, shared with the server's idle loop + revocation. `None`
    /// (with `db_auth_callback`) also disables the ingress.
    pub db_relay_registry: Option<Arc<db_relay::DbRelayRegistry>>,
    /// Total concurrent live DB relays (post-auth ceiling).
    pub db_max_concurrent: usize,
    /// Concurrent unauthenticated DB handshake→preamble reads ([R6]).
    pub db_preauth_max: usize,
    /// Concurrent unauthenticated preamble reads allowed from a SINGLE source IP ([R6]) —
    /// the per-IP dimension the global `db_preauth_max` lacks, so one host can't hold every
    /// preauth slot for the full preamble deadline and starve the DB reach plane platform-wide.
    pub db_preauth_per_ip_max: usize,
    /// Per-project live DB-relay cap.
    pub db_max_per_project: usize,
}

struct SharedState {
    routes: RoutingTable,
    domain: Arc<String>,
    api_addr: Arc<Option<String>>,
    storage_addr: Arc<Option<String>>,
    auth_addr: Arc<Option<String>>,
    domains: Option<DomainMap>,
    activity: Option<ActivityTracker>,
    wake_cb: Option<WakeCallback>,
    backend_port: u16,
    relay_idle_timeout: Duration,
    /// Permits for in-flight relayed upgrades; a relay holds one for its lifetime.
    relay_permits: Arc<tokio::sync::Semaphore>,
    /// The managed-DB reach-plane edge, or `None` when the ingress is not configured.
    db_ingress: Option<Arc<db_ingress::DbIngress>>,
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
    let domain = Arc::new(config.platform_domain);
    let activity = config.activity_tracker;
    // Assemble the managed-DB reach-plane edge iff its auth + registry + wake are all
    // configured; otherwise a `jkbase-db`-ALPN connection is dropped at the demux.
    let db_ingress = match (
        config.db_auth_callback,
        config.db_relay_registry,
        config.wake_callback.clone(),
    ) {
        (Some(auth), Some(registry), Some(wake)) => Some(Arc::new(db_ingress::DbIngress {
            domain: domain.clone(),
            auth,
            wake,
            registry,
            activity: activity.clone(),
            backend_port: config.backend_port,
            global: Arc::new(tokio::sync::Semaphore::new(config.db_max_concurrent)),
            preauth: Arc::new(tokio::sync::Semaphore::new(config.db_preauth_max)),
            per_ip: db_ingress::PerIpLimiter::new(config.db_preauth_per_ip_max),
            per_project_max: config.db_max_per_project,
        })),
        _ => None,
    };
    let shared = Arc::new(SharedState {
        routes,
        domain,
        api_addr: Arc::new(config.api_addr),
        storage_addr: Arc::new(config.storage_addr),
        auth_addr: Arc::new(config.auth_addr),
        domains: config.domains,
        activity,
        wake_cb: config.wake_callback,
        backend_port: config.backend_port,
        relay_idle_timeout: config.relay_idle_timeout,
        relay_permits: Arc::new(tokio::sync::Semaphore::new(config.max_concurrent_upgrades)),
        db_ingress,
    });

    // [R-drain] A raw DB relay never EOFs on its own, so on shutdown force-close every live
    // one — otherwise each would pin the drain barrier below until the hard DRAIN_GRACE
    // process-exit. Their `RelayHooks.cancel` (the registry token) ends them promptly.
    if let Some(ingress) = &shared.db_ingress {
        let registry = ingress.registry.clone();
        let sd = shutdown.clone();
        tokio::spawn(async move {
            sd.cancelled().await;
            let n = registry.cancel_all();
            if n > 0 {
                info!(count = n, "force-closing db relays for drain");
            }
        });
    }

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
        let (stream, peer) = tokio::select! {
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
            let client = ClientInfo {
                ip: peer.ip(),
                proto: "http",
            };
            let svc = service_fn(move |req| proxy_request(shared.clone(), client, req));
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
        let (stream, peer) = tokio::select! {
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
            // ALPN demux (D3): a connection that negotiated `jkbase-db` is the managed-DB
            // reach plane — route it to the DB ingress and NEVER into the HTTP host-router,
            // so a `.db.*` host can't be woken by an unauthenticated HTTP request ([R6]/[R7]).
            // A db-ALPN connection with the ingress unconfigured is dropped. This task holds
            // `_permit` (drain-barrier membership) for the relay's whole life; the drain
            // deadline force-closes it via the registry (see `serve`).
            if tls_stream.get_ref().1.alpn_protocol() == Some(db_preamble::DB_ALPN) {
                if let Some(ingress) = shared.db_ingress.clone() {
                    ingress.handle(tls_stream, peer.ip()).await;
                }
                return;
            }
            let io = TokioIo::new(tls_stream);
            let client = ClientInfo {
                ip: peer.ip(),
                proto: "https",
            };
            let svc = service_fn(move |req| proxy_request(shared.clone(), client, req));
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
    client: ClientInfo,
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
        return match forward_to_api(&shared, addr, client, req).await {
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
        return match forward_to_api(&shared, addr, client, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(error = %e, "object-store forward failed");
                Ok(bad_gateway())
            }
        };
    }

    // Route auth.{domain} to the jkbase-Auth issuer service (P3; infra host, never a tenant
    // project — `auth` is a RESERVED_LABEL). Same local-forward pattern as storage; the issuer
    // reads the project from the path + the `jkbk_` bearer, so the Host rewrite is harmless.
    if subdomain.as_deref() == Some("auth")
        && let Some(ref addr) = *shared.auth_addr
    {
        return match forward_to_api(&shared, addr, client, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(error = %e, "jkbase-auth forward failed");
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
        return match forward_request(&shared, &ip, &project_id, site, client, req).await {
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
        Ok(ip) => match forward_request(&shared, &ip, &project_id, site, client, req).await {
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
        Err(WakeError::RateLimited(reason)) => {
            // Throttled (per-project backoff / plane rate cap) — same client-facing shape as a
            // transient failure: retry shortly.
            info!(project = %project_id, %reason, "refusing wake: rate limited");
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
    on_activity: Option<Arc<dyn Fn() + Send + Sync>>,
) -> Response<ProxyBody> {
    use jkbase_wsproxy::UpgradeOutcome;
    match jkbase_wsproxy::spawn_upgrade_relay(
        client_upgrade,
        &mut backend_resp,
        shared.relay_idle_timeout,
        &shared.relay_permits,
        on_activity,
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

/// The verified facts about a client connection that a backend cannot otherwise learn: who
/// connected, and over what scheme. Sourced from the accepted socket and the listener that
/// accepted it — never from anything on the wire.
#[derive(Debug, Clone, Copy)]
pub struct ClientInfo {
    pub ip: std::net::IpAddr,
    /// `"https"` or `"http"` — which listener took the connection, not a client claim.
    pub proto: &'static str,
}

/// Headers that name the CLIENT. The proxy is the sole authority for every one of them — a client
/// can set any of these on the wire, so an inbound copy is unauthenticated and must never reach a
/// backend (the same discipline [`SITE_HEADER`] already gets).
const CLIENT_IDENTITY_HEADERS: [&str; 4] = [
    "x-forwarded-for",
    "x-real-ip",
    "forwarded",
    "x-forwarded-proto",
];

fn is_client_identity_header(name: &str) -> bool {
    // Underscores are folded to dashes before comparing, so `X_Forwarded_For` is stripped too.
    // It is a DIFFERENT header name on the wire — a tenant reading `X-Forwarded-For` would never
    // see it — but CGI-style environments (WSGI, CGI, nginx with `underscores_in_headers on`)
    // normalize `-` to `_`, so both names collapse to a single `HTTP_X_FORWARDED_FOR` key and the
    // attacker's copy can win the collision. jkbase ships a Python buildpack, so that is a real
    // path, and the classic way this exact defence gets bypassed.
    let normalized = name.to_ascii_lowercase().replace('_', "-");
    CLIENT_IDENTITY_HEADERS.contains(&normalized.as_str())
}

/// RFC 7239 node identifier: an IPv6 literal must be bracketed AND quoted, because the bare form
/// contains `:`, the parameter separator. Getting this wrong yields a value parsers silently
/// truncate at the first colon — every v6 client would be attributed to `2001`.
fn forwarded_node(ip: std::net::IpAddr) -> String {
    match ip {
        std::net::IpAddr::V4(v4) => format!("for={v4}"),
        std::net::IpAddr::V6(v6) => format!("for=\"[{v6}]\""),
    }
}

/// Build the header set for a backend: the client's headers minus everything the proxy is
/// authoritative for, plus the verified client identity.
///
/// **These values REPLACE any inbound ones; they are never appended to.** The conventional proxy
/// behaviour (append to `X-Forwarded-For`, tell the app to read the last entry) hands the backend
/// a list whose leading entries are attacker-chosen, and mis-reading it is one of the most common
/// ways an IP allow/deny list becomes forgeable. jkbase is the only hop in front of a tenant, so
/// the honest representation is a single verified address — and a tenant that reads
/// `X-Forwarded-For` naively still gets the right answer.
///
/// `drop_host` is for backends addressed by IP (the control API), where the client's `Host` is
/// meaningless; a tenant VM keeps it, since in-app virtual-host routing depends on it.
fn build_forward_headers(
    src: &hyper::HeaderMap,
    client: ClientInfo,
    drop_host: bool,
) -> hyper::HeaderMap {
    let mut out = hyper::HeaderMap::with_capacity(src.len() + CLIENT_IDENTITY_HEADERS.len());
    for (key, value) in src {
        let name = key.as_str();
        if drop_host && name == "host" {
            continue;
        }
        if name.to_ascii_lowercase() == SITE_HEADER || is_client_identity_header(name) {
            continue;
        }
        out.append(key.clone(), value.clone());
    }

    // An IP's Display output is always a valid header value, but take the fallible path anyway:
    // a panic here would be on every request.
    let ip = client.ip.to_string();
    if let Ok(v) = hyper::header::HeaderValue::from_str(&ip) {
        out.insert("x-forwarded-for", v.clone());
        out.insert("x-real-ip", v);
    }
    if let Ok(v) = hyper::header::HeaderValue::from_str(&forwarded_node(client.ip)) {
        out.insert("forwarded", v);
    }
    if let Ok(v) = hyper::header::HeaderValue::from_str(client.proto) {
        out.insert("x-forwarded-proto", v);
    }
    out
}

async fn forward_to_api(
    shared: &SharedState,
    api_addr: &str,
    client: ClientInfo,
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

    // Strips host, the trusted internal site header, and any client-supplied identity headers,
    // then stamps the verified ones (anti-spoof).
    let mut builder = Request::builder().method(req.method()).uri(&uri);
    for (key, value) in &build_forward_headers(req.headers(), client, true) {
        builder = builder.header(key, value);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    let resp = sender.send_request(proxy_req).await?;
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Infra hosts (api/storage/auth): keep their HSTS (`strip_hsts = false`) and never
        // re-stamp — they are in-process loopback services, not hibernatable tenant VMs.
        return Ok(relay_upgrade(client_upgrade, resp, shared, false, None));
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
    project_id: &str,
    site: Option<&str>,
    client: ClientInfo,
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

    // Drops any inbound site header (a client must not pick the served site) and any inbound
    // client-identity headers, then stamps the verified client IP + scheme. The proxy is the sole
    // authority for all of them.
    let mut builder = Request::builder().method(req.method()).uri(&uri);
    for (key, value) in &build_forward_headers(req.headers(), client, false) {
        builder = builder.header(key, value);
    }
    if let Some(site) = site {
        builder = builder.header(SITE_HEADER, site);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    let resp = sender.send_request(proxy_req).await?;
    // Re-stamp activity on frame flow so a long-lived WS splice or streamed response keeps its
    // VM warm — the connection never re-enters `proxy_request` after this (wake-on-WS).
    let on_activity = activity_stamp(&shared.activity, project_id);
    if resp.status() == StatusCode::SWITCHING_PROTOCOLS {
        // Tenant backend (untrusted): strip HSTS too — the platform owns transport
        // policy for `*.{domain}`.
        return Ok(relay_upgrade(
            client_upgrade,
            resp,
            shared,
            true,
            on_activity,
        ));
    }
    let status = resp.status();
    let mut headers = resp.headers().clone();
    jkbase_wsproxy::sanitize_response_headers(&mut headers, &shared.domain, true, false);
    // Stream the backend body through instead of buffering it in proxy RAM — an
    // object download (or any large tenant response) must not sit wholly in memory.
    let raw = resp.into_body().map_err(std::io::Error::other).boxed();
    // Wrap streamed bodies so an SSE/chunked stream re-stamps activity per frame (throttled);
    // a short response completes before the throttle re-fires, so this is a no-op for it.
    let body = match on_activity {
        Some(stamp) => ActivityBody::new(raw, stamp).boxed(),
        None => raw,
    };

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

    fn client(ip: &str) -> ClientInfo {
        ClientInfo {
            ip: ip.parse().unwrap(),
            proto: "https",
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        for (k, v) in pairs {
            h.append(
                hyper::header::HeaderName::from_bytes(k.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        h
    }

    #[test]
    fn client_identity_is_stamped_from_the_socket() {
        let out =
            build_forward_headers(&headers(&[("accept", "*/*")]), client("203.0.113.7"), false);
        assert_eq!(out["x-forwarded-for"], "203.0.113.7");
        assert_eq!(out["x-real-ip"], "203.0.113.7");
        assert_eq!(out["forwarded"], "for=203.0.113.7");
        assert_eq!(out["x-forwarded-proto"], "https");
        // Everything else still rides through.
        assert_eq!(out["accept"], "*/*");
    }

    #[test]
    fn underscore_variants_are_stripped_too() {
        // `X_Forwarded_For` is a different header name on the wire, so a tenant reading
        // `X-Forwarded-For` would never see it — but CGI-style environments (WSGI, CGI, nginx with
        // `underscores_in_headers on`) fold `-` to `_`, so both collapse to one
        // `HTTP_X_FORWARDED_FOR` key and the attacker's copy can win. This is the classic bypass
        // of exactly this defence, and jkbase ships a Python buildpack.
        let src = headers(&[
            ("X_Forwarded_For", "1.2.3.4"),
            ("X_Real_IP", "1.2.3.4"),
            ("X_Forwarded_Proto", "http"),
        ]);
        let out = build_forward_headers(&src, client("203.0.113.7"), false);
        for name in ["x_forwarded_for", "x_real_ip", "x_forwarded_proto"] {
            assert!(
                out.get(name).is_none(),
                "{name} reached the backend and can collide with the real one under CGI folding"
            );
        }
        assert_eq!(out["x-forwarded-for"], "203.0.113.7");
    }

    #[test]
    fn duplicate_and_mixed_case_identity_headers_collapse_to_the_verified_one() {
        // An appending proxy would leave the attacker's value first; a strip that removed only the
        // FIRST duplicate would leave a second behind. Exactly one value must survive.
        let mut src = hyper::HeaderMap::new();
        for (n, v) in [
            ("x-forwarded-for", "1.1.1.1"),
            ("x-forwarded-for", "2.2.2.2"),
        ] {
            src.append(
                hyper::header::HeaderName::from_bytes(n.as_bytes()).unwrap(),
                hyper::header::HeaderValue::from_str(v).unwrap(),
            );
        }
        src.append(
            hyper::header::HeaderName::from_bytes(b"X-ForWarded-For").unwrap(),
            hyper::header::HeaderValue::from_static("3.3.3.3"),
        );
        let out = build_forward_headers(&src, client("203.0.113.7"), false);
        let vals: Vec<_> = out.get_all("x-forwarded-for").iter().collect();
        assert_eq!(vals.len(), 1, "more than one X-Forwarded-For reached the backend");
        assert_eq!(vals[0], "203.0.113.7");
    }

    #[test]
    fn spoofed_client_identity_is_replaced_not_appended() {
        // The whole point: a tenant reading X-Forwarded-For naively must not be able to be lied
        // to. An APPENDING proxy would leave "1.2.3.4" as the first entry and hand a naive
        // `split(',').next()` the attacker's value.
        let src = headers(&[
            ("x-forwarded-for", "1.2.3.4"),
            ("X-Real-IP", "1.2.3.4"),
            ("Forwarded", "for=1.2.3.4"),
            ("x-forwarded-proto", "http"),
        ]);
        let out = build_forward_headers(&src, client("203.0.113.7"), false);

        for name in [
            "x-forwarded-for",
            "x-real-ip",
            "forwarded",
            "x-forwarded-proto",
        ] {
            assert_eq!(
                out.get_all(name).iter().count(),
                1,
                "{name} must be a single authoritative value, never a chain"
            );
        }
        assert_eq!(out["x-forwarded-for"], "203.0.113.7");
        assert_eq!(out["x-real-ip"], "203.0.113.7");
        assert_eq!(out["forwarded"], "for=203.0.113.7");
        assert_eq!(out["x-forwarded-proto"], "https");
    }

    #[test]
    fn spoofed_site_header_is_still_dropped() {
        let out = build_forward_headers(
            &headers(&[(SITE_HEADER, "other")]),
            client("203.0.113.7"),
            false,
        );
        assert!(out.get(SITE_HEADER).is_none());
    }

    #[test]
    fn ipv6_forwarded_node_is_bracketed_and_quoted() {
        // RFC 7239: a bare v6 literal contains the parameter separator, so parsers truncate it
        // at the first colon and every v6 client is attributed to "2001".
        assert_eq!(
            forwarded_node("2001:db8::1".parse().unwrap()),
            "for=\"[2001:db8::1]\""
        );
        assert_eq!(
            forwarded_node("203.0.113.7".parse().unwrap()),
            "for=203.0.113.7"
        );

        let out = build_forward_headers(&hyper::HeaderMap::new(), client("2001:db8::1"), false);
        assert_eq!(out["x-forwarded-for"], "2001:db8::1");
        assert_eq!(out["forwarded"], "for=\"[2001:db8::1]\"");
    }

    #[test]
    fn host_is_dropped_only_for_ip_addressed_backends() {
        let src = headers(&[("host", "app.jkbase.app")]);
        // Tenant VM: keeps Host (in-app virtual-host routing depends on it).
        assert!(
            build_forward_headers(&src, client("203.0.113.7"), false)
                .get("host")
                .is_some()
        );
        // Control API, addressed by IP: Host is meaningless.
        assert!(
            build_forward_headers(&src, client("203.0.113.7"), true)
                .get("host")
                .is_none()
        );
    }

    #[test]
    fn identity_header_match_is_case_insensitive() {
        assert!(is_client_identity_header("X-Forwarded-For"));
        assert!(is_client_identity_header("x-real-ip"));
        assert!(is_client_identity_header("FORWARDED"));
        assert!(!is_client_identity_header("x-forwarded-for-real"));
        assert!(!is_client_identity_header("user-agent"));
    }

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

    /// An inner body that yields each queued buffer as a data frame, then ends.
    struct FramesBody(Vec<Bytes>);
    impl Body for FramesBody {
        type Data = Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            mut self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, std::io::Error>>> {
            if self.0.is_empty() {
                Poll::Ready(None)
            } else {
                Poll::Ready(Some(Ok(Frame::data(self.0.remove(0)))))
            }
        }
    }

    fn counting_stamp() -> (Arc<std::sync::atomic::AtomicUsize>, Arc<dyn Fn() + Send + Sync>) {
        use std::sync::atomic::{AtomicUsize, Ordering};
        let hits = Arc::new(AtomicUsize::new(0));
        let cb = {
            let hits = hits.clone();
            Arc::new(move || {
                hits.fetch_add(1, Ordering::SeqCst);
            }) as Arc<dyn Fn() + Send + Sync>
        };
        (hits, cb)
    }

    // A FRESH stream (last seeded at construction) adds NO extra stamp — the request-start stamp
    // already covers t=0, so a short/normal response within the interval never re-stamps.
    #[tokio::test]
    async fn activity_body_fresh_stream_adds_no_stamp() {
        use std::sync::atomic::Ordering;
        let (hits, stamp) = counting_stamp();
        let inner = FramesBody(vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
        let mut body = ActivityBody::new(inner, stamp);
        while let Some(frame) = body.frame().await {
            frame.unwrap();
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "a fresh short stream is covered by the request-start stamp and must add none"
        );
    }

    // A stream that has OUTLIVED the interval re-stamps on its next data frame, then throttles:
    // the second frame (within the reset window) is suppressed.
    #[tokio::test]
    async fn activity_body_restamps_once_past_interval() {
        use std::sync::atomic::Ordering;
        let (hits, stamp) = counting_stamp();
        let inner = FramesBody(vec![Bytes::from_static(b"a"), Bytes::from_static(b"b")]);
        // Seed `last` well into the past so the first data frame is due.
        let aged = Instant::now()
            .checked_sub(jkbase_wsproxy::ACTIVITY_STAMP_INTERVAL * 2)
            .expect("monotonic clock older than 60s");
        let mut body = ActivityBody {
            inner,
            stamp,
            last: aged,
        };
        while let Some(frame) = body.frame().await {
            frame.unwrap();
        }
        assert_eq!(
            hits.load(Ordering::SeqCst),
            1,
            "a stream past the interval re-stamps once; the next frame is throttled"
        );
    }

    // A trailers-only / empty body carries no traffic, so it must NOT stamp even when aged.
    #[tokio::test]
    async fn activity_body_ignores_trailers_only_frame() {
        use std::sync::atomic::Ordering;
        let (hits, stamp) = counting_stamp();
        let aged = Instant::now()
            .checked_sub(jkbase_wsproxy::ACTIVITY_STAMP_INTERVAL * 2)
            .expect("monotonic clock older than 60s");
        let mut body = ActivityBody {
            inner: FramesBody(vec![]),
            stamp,
            last: aged,
        };
        while let Some(frame) = body.frame().await {
            frame.unwrap();
        }
        assert_eq!(hits.load(Ordering::SeqCst), 0, "no data frame → no stamp");
    }
}
