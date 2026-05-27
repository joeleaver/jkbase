pub mod tls;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::{HashMap, HashSet};
use std::future::Future;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::time::Instant;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

pub type RoutingTable = Arc<RwLock<HashMap<String, String>>>;
pub type KnownProjects = Arc<RwLock<HashSet<String>>>;
pub type ActivityTracker = Arc<RwLock<HashMap<String, Instant>>>;
pub type WakeCallback = Arc<
    dyn Fn(String) -> Pin<Box<dyn Future<Output = Result<String>> + Send>> + Send + Sync,
>;

pub fn new_routing_table() -> RoutingTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub struct ProxyConfig {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub platform_domain: String,
    pub tls_config: Option<tls::TlsConfig>,
    pub api_addr: Option<String>,
    pub known_projects: Option<KnownProjects>,
    pub activity_tracker: Option<ActivityTracker>,
    pub wake_callback: Option<WakeCallback>,
}

struct SharedState {
    routes: RoutingTable,
    domain: Arc<String>,
    api_addr: Arc<Option<String>>,
    known_projects: Option<KnownProjects>,
    activity: Option<ActivityTracker>,
    wake_cb: Option<WakeCallback>,
}

pub async fn serve(config: ProxyConfig, routes: RoutingTable) -> Result<()> {
    let shared = Arc::new(SharedState {
        routes,
        domain: Arc::new(config.platform_domain),
        api_addr: Arc::new(config.api_addr),
        known_projects: config.known_projects,
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

    // Route api.{domain} to the control plane
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

    let project_id = match subdomain.as_deref() {
        None => "www".to_string(),
        Some("www") => "www".to_string(),
        Some(sub) => sub.to_string(),
    };

    // Record activity for idle detection
    if let Some(ref tracker) = shared.activity {
        let mut t = tracker.write().await;
        t.insert(project_id.clone(), Instant::now());
    }

    // Fast path: VM is running, forward immediately
    let backend_ip = {
        let table = shared.routes.read().await;
        table.get(&project_id).cloned()
    };

    if let Some(ip) = backend_ip {
        return match forward_request(&ip, req).await {
            Ok(resp) => Ok(resp),
            Err(e) => {
                error!(project = %project_id, error = %e, "backend request failed");
                Ok(bad_gateway())
            }
        };
    }

    // Not in routing table. Is it a known project? (might be hibernated)
    let is_known = if let Some(ref kp) = shared.known_projects {
        let set = kp.read().await;
        set.contains(&project_id)
    } else {
        false
    };

    if !is_known {
        return Ok(not_found(&project_id));
    }

    // Known project but not running — wake it
    let Some(ref cb) = shared.wake_cb else {
        return Ok(not_found(&project_id));
    };

    info!(project = %project_id, "waking hibernated project");
    match (cb)(project_id.clone()).await {
        Ok(ip) => match forward_request(&ip, req).await {
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
        if key != "host" {
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
        builder = builder.header(key, value);
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
}
