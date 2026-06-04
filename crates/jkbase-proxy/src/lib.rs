pub mod tls;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
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
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

/// Running backends: host-key → VM IP (fast path; only entries for live VMs).
pub type RoutingTable = Arc<RwLock<HashMap<String, String>>>;
pub type ActivityTracker = Arc<RwLock<HashMap<String, Instant>>>;
pub type WakeCallback = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send + Sync,
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

pub struct ProxyConfig {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub platform_domain: String,
    pub tls_config: Option<tls::TlsConfig>,
    pub api_addr: Option<String>,
    pub domains: Option<DomainMap>,
    pub activity_tracker: Option<ActivityTracker>,
    pub wake_callback: Option<WakeCallback>,
}

struct SharedState {
    routes: RoutingTable,
    domain: Arc<String>,
    api_addr: Arc<Option<String>>,
    domains: Option<DomainMap>,
    activity: Option<ActivityTracker>,
    wake_cb: Option<WakeCallback>,
}

pub async fn serve(config: ProxyConfig, routes: RoutingTable) -> Result<()> {
    let shared = Arc::new(SharedState {
        routes,
        domain: Arc::new(config.platform_domain),
        api_addr: Arc::new(config.api_addr),
        domains: config.domains,
        activity: config.activity_tracker,
        wake_cb: config.wake_callback,
    });

    if let (Some(https_port), Some(tls_cfg)) = (config.https_port, &config.tls_config) {
        let rustls_config = tls::load_or_provision_tls(tls_cfg).await?;
        let acceptor = TlsAcceptor::from(rustls_config);

        let shared_tls = shared.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https(https_port, acceptor, shared_tls).await {
                error!(error = %e, "HTTPS proxy error");
            }
        });

        serve_http_redirect(config.http_port, shared.domain.clone()).await
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
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
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
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "HTTPS connection error");
            }
        });
    }
}

async fn serve_http_redirect(port: u16, domain: Arc<String>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP->HTTPS redirect listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let domain = domain.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req: Request<hyper::body::Incoming>| {
                let host = req
                    .headers()
                    .get("host")
                    .and_then(|h| h.to_str().ok())
                    .unwrap_or(&domain)
                    .to_string();
                let path = req
                    .uri()
                    .path_and_query()
                    .map(|pq| pq.as_str())
                    .unwrap_or("/");
                let location = format!("https://{host}{path}");
                async move {
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
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let hostname = host.split(':').next().unwrap_or("");
    let subdomain = extract_subdomain(hostname, &shared.domain);

    // Route api.{domain} to the control plane (infra, never a tenant project).
    if subdomain.as_deref() == Some("api") {
        if let Some(ref addr) = *shared.api_addr {
            return match forward_to_api(addr, req).await {
                Ok(resp) => Ok(resp),
                Err(e) => {
                    error!(error = %e, "API forward failed");
                    Ok(bad_gateway())
                }
            };
        }
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
        Err(e) => {
            error!(project = %project_id, error = %e, "failed to wake project");
            Ok(Response::builder()
                .status(StatusCode::SERVICE_UNAVAILABLE)
                .header("Content-Type", "text/plain")
                .header("Retry-After", "5")
                .body(Full::new(Bytes::from("project is starting up, please retry")))
                .unwrap())
        }
    }
}

fn bad_gateway() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from("bad gateway")))
        .unwrap()
}

fn not_found(project_id: &str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("Content-Type", "text/plain")
        .body(Full::new(Bytes::from(format!(
            "project not found: '{project_id}'"
        ))))
        .unwrap()
}

async fn forward_to_api(
    api_addr: &str,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{api_addr}{path}");

    let stream = tokio::net::TcpStream::connect(api_addr).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let mut builder = Request::builder().method(req.method()).uri(&uri);
    for (key, value) in req.headers() {
        // Strip host and the trusted internal site header (anti-spoof).
        if key != "host" && key.as_str().to_ascii_lowercase() != SITE_HEADER {
            builder = builder.header(key, value);
        }
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    let resp = sender.send_request(proxy_req).await?;
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();

    let mut builder = Response::builder().status(status);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    Ok(builder.body(Full::new(body)).unwrap())
}

async fn forward_request(
    backend_ip: &str,
    site: Option<&str>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/");
    let uri = format!("http://{}:{}{}", backend_ip, 80, path_and_query);

    let stream = tokio::net::TcpStream::connect(format!("{backend_ip}:80")).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

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
    let status = resp.status();
    let headers = resp.headers().clone();
    let body = resp.into_body().collect().await?.to_bytes();

    let mut builder = Response::builder().status(status);
    for (key, value) in &headers {
        builder = builder.header(key, value);
    }
    Ok(builder.body(Full::new(body)).unwrap())
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
