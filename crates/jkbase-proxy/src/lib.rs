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
use tokio_rustls::TlsAcceptor;
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
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String, WakeError>> + Send>>
        + Send
        + Sync,
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
}

struct SharedState {
    routes: RoutingTable,
    domain: Arc<String>,
    api_addr: Arc<Option<String>>,
    storage_addr: Arc<Option<String>>,
    domains: Option<DomainMap>,
    activity: Option<ActivityTracker>,
    wake_cb: Option<WakeCallback>,
}

pub async fn serve(config: ProxyConfig, routes: RoutingTable) -> Result<()> {
    let shared = Arc::new(SharedState {
        routes,
        domain: Arc::new(config.platform_domain),
        api_addr: Arc::new(config.api_addr),
        storage_addr: Arc::new(config.storage_addr),
        domains: config.domains,
        activity: config.activity_tracker,
        wake_cb: config.wake_callback,
    });

    if let (Some(https_port), Some(cert_manager)) = (config.https_port, config.cert_manager.clone())
    {
        let acceptor = TlsAcceptor::from(cert_manager.server_config());
        cert_manager.spawn_reconcile();

        let shared_tls = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https(https_port, acceptor, shared_tls).await {
                error!(error = %e, "HTTPS proxy error");
            }
        });

        serve_http_redirect(config.http_port, shared.domain.clone(), cert_manager).await
    } else {
        serve_http(config.http_port, shared).await
    }
}

async fn serve_http(port: u16, shared: Arc<SharedState>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, domain = %shared.domain, "HTTP proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let shared = shared.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy_request(shared.clone(), req));
            // with_upgrades(): keep driving the connection after a 101 so a
            // proxied WebSocket (or other Upgrade) can reclaim the raw stream.
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!(error = %e, "proxy connection error");
            }
        });
    }
}

async fn serve_https(port: u16, acceptor: TlsAcceptor, shared: Arc<SharedState>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, domain = %shared.domain, "HTTPS proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let shared = shared.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |req| proxy_request(shared.clone(), req));
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!(error = %e, "HTTPS connection error");
            }
        });
    }
}

async fn serve_http_redirect(
    port: u16,
    domain: Arc<String>,
    cert_manager: Arc<tls::CertManager>,
) -> Result<()> {
    const ACME_PREFIX: &str = "/.well-known/acme-challenge/";
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP->HTTPS redirect listening (with ACME HTTP-01)");

    loop {
        let (stream, _peer) = listener.accept().await?;
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
                    let pq = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
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
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "redirect connection error");
            }
        });
    }
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
        && let Some(ref addr) = *shared.api_addr {
            return match forward_to_api(addr, req).await {
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
        && let Some(ref addr) = *shared.storage_addr {
            return match forward_to_api(addr, req).await {
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
        return match forward_request(&ip, site, req).await {
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
        Ok(ip) => match forward_request(&ip, site, req).await {
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

/// Did the client ask to switch protocols (e.g. a WebSocket handshake)?
/// `Connection: Upgrade` + an `Upgrade:` token, per RFC 9110 §7.8.
fn is_upgrade_request(headers: &hyper::HeaderMap) -> bool {
    let connection_upgrade = headers
        .get(hyper::header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.split(',').any(|t| t.trim().eq_ignore_ascii_case("upgrade")))
        .unwrap_or(false);
    connection_upgrade && headers.contains_key(hyper::header::UPGRADE)
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

/// If no bytes flow in either direction for this long, a spliced upgrade
/// (WebSocket, etc.) is torn down. Active traffic — including WebSocket
/// ping/pong keepalives — resets the timer, so legitimate long-lived
/// connections are unaffected; only abandoned or deliberately-idle sockets are
/// reaped. Without this, a peer that completes the handshake and then stalls
/// would pin two fds plus two relay tasks on the *shared* edge proxy forever.
const RELAY_IDLE_TIMEOUT: Duration = Duration::from_secs(600);

/// Splice two upgraded byte streams together, reaping the relay if it goes idle
/// for [`RELAY_IDLE_TIMEOUT`]. This replaces a bare `copy_bidirectional`, which
/// only returns once *both* directions close and so never reaps a wedged
/// half-open connection.
async fn relay_bidirectional<A, B>(client: A, backend: B)
where
    A: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
    B: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (mut client_rd, mut client_wr) = tokio::io::split(client);
    let (mut backend_rd, mut backend_wr) = tokio::io::split(backend);
    let activity = Arc::new(tokio::sync::Notify::new());

    let to_backend = {
        let activity = activity.clone();
        async move {
            let mut buf = [0u8; 8192];
            loop {
                match client_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if backend_wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        activity.notify_one();
                    }
                }
            }
            // Propagate the half-close so the other side sees EOF.
            let _ = backend_wr.shutdown().await;
        }
    };

    let to_client = {
        let activity = activity.clone();
        async move {
            let mut buf = [0u8; 8192];
            loop {
                match backend_rd.read(&mut buf).await {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if client_wr.write_all(&buf[..n]).await.is_err() {
                            break;
                        }
                        activity.notify_one();
                    }
                }
            }
            let _ = client_wr.shutdown().await;
        }
    };

    // The idle watchdog: each loop resets when either pump signals traffic, and
    // fires only after a full idle window with no activity.
    let idle = async {
        loop {
            tokio::select! {
                _ = activity.notified() => {}
                _ = tokio::time::sleep(RELAY_IDLE_TIMEOUT) => break,
            }
        }
    };

    tokio::select! {
        _ = async { tokio::join!(to_backend, to_client) } => {}
        _ = idle => info!("upgrade relay idle timeout; closing"),
    }
}

/// A backend answered `101 Switching Protocols`. Splice the two upgraded byte
/// streams together once both ends complete, and return the 101 verbatim so
/// hyper finishes the client-side switch (it only does this because the
/// listener runs `serve_connection(...).with_upgrades()`).
///
/// `client_upgrade` is the `OnUpgrade` captured from the inbound request BEFORE
/// its body was moved into the backend request — capturing it afterward is too
/// late, the extension is gone.
fn relay_upgrade(
    client_upgrade: Option<hyper::upgrade::OnUpgrade>,
    mut backend_resp: Response<hyper::body::Incoming>,
) -> Response<ProxyBody> {
    let backend_upgrade = hyper::upgrade::on(&mut backend_resp);
    match client_upgrade {
        Some(client_upgrade) => {
            tokio::spawn(async move {
                match tokio::join!(client_upgrade, backend_upgrade) {
                    (Ok(client), Ok(backend)) => {
                        relay_bidirectional(TokioIo::new(client), TokioIo::new(backend)).await;
                    }
                    (c, b) => error!(
                        client_err = ?c.err(),
                        backend_err = ?b.err(),
                        "protocol upgrade failed; dropping connection"
                    ),
                }
            });
        }
        // Backend switched protocols but the client never asked to: nothing to
        // splice to. Return the 101 anyway; hyper has no upgrade to fulfil.
        None => error!("backend sent 101 without a client upgrade request"),
    }

    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
    for (key, value) in backend_resp.headers() {
        builder = builder.header(key, value);
    }
    builder.body(full_body(Bytes::new())).unwrap()
}

async fn forward_to_api(
    api_addr: &str,
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{api_addr}{path}");

    let upgrade = is_upgrade_request(req.headers());
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
        return Ok(relay_upgrade(client_upgrade, resp));
    }
    let status = resp.status();
    let headers = resp.headers().clone();
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
    backend_ip: &str,
    site: Option<&str>,
    mut req: Request<hyper::body::Incoming>,
) -> Result<Response<ProxyBody>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{}:{}{}", backend_ip, 80, path_and_query);

    // Capture the client-side upgrade future before the body is consumed below.
    let upgrade = is_upgrade_request(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = tokio::net::TcpStream::connect(format!("{backend_ip}:80")).await?;
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
        return Ok(relay_upgrade(client_upgrade, resp));
    }
    let status = resp.status();
    let headers = resp.headers().clone();
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

    fn upgrade_headers(connection: Option<&str>, upgrade: Option<&str>) -> hyper::HeaderMap {
        let mut h = hyper::HeaderMap::new();
        if let Some(c) = connection {
            h.insert(hyper::header::CONNECTION, c.parse().unwrap());
        }
        if let Some(u) = upgrade {
            h.insert(hyper::header::UPGRADE, u.parse().unwrap());
        }
        h
    }

    #[test]
    fn detects_websocket_upgrade() {
        // Bare `Connection: Upgrade` + an Upgrade header.
        assert!(is_upgrade_request(&upgrade_headers(
            Some("Upgrade"),
            Some("websocket")
        )));
        // The comma-list form real browsers send (`keep-alive, Upgrade`).
        assert!(is_upgrade_request(&upgrade_headers(
            Some("keep-alive, Upgrade"),
            Some("websocket")
        )));
        // Token match is case-insensitive.
        assert!(is_upgrade_request(&upgrade_headers(
            Some("upgrade"),
            Some("WebSocket")
        )));
    }

    #[test]
    fn rejects_non_upgrade_requests() {
        // No upgrade signalling at all.
        assert!(!is_upgrade_request(&upgrade_headers(None, None)));
        // Connection has the token but the Upgrade header is missing.
        assert!(!is_upgrade_request(&upgrade_headers(Some("Upgrade"), None)));
        // Upgrade header present but Connection never lists the token.
        assert!(!is_upgrade_request(&upgrade_headers(
            Some("keep-alive"),
            Some("websocket")
        )));
        // Full-token match, not substring: `upgrade-insecure-requests` as a
        // Connection token must NOT count as an upgrade.
        assert!(!is_upgrade_request(&upgrade_headers(
            Some("upgrade-insecure-requests"),
            Some("websocket")
        )));
    }

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
