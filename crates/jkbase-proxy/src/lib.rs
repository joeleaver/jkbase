pub mod tls;

use anyhow::Result;
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio_rustls::TlsAcceptor;
use tracing::{error, info};

pub type RoutingTable = Arc<RwLock<HashMap<String, String>>>;

pub fn new_routing_table() -> RoutingTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub struct ProxyConfig {
    pub http_port: u16,
    pub https_port: Option<u16>,
    pub platform_domain: String,
    pub tls_config: Option<tls::TlsConfig>,
}

pub async fn serve(config: ProxyConfig, routes: RoutingTable) -> Result<()> {
    let platform_domain = Arc::new(config.platform_domain);

    // If TLS is configured, provision cert and serve HTTPS
    if let (Some(https_port), Some(tls_cfg)) = (config.https_port, &config.tls_config) {
        let rustls_config = tls::load_or_provision_tls(tls_cfg).await?;
        let acceptor = TlsAcceptor::from(rustls_config);

        // Spawn HTTPS listener
        let routes_tls = routes.clone();
        let domain_tls = platform_domain.clone();
        let acceptor_clone = acceptor.clone();
        tokio::spawn(async move {
            if let Err(e) = serve_https(https_port, acceptor_clone, routes_tls, domain_tls).await {
                error!(error = %e, "HTTPS proxy error");
            }
        });

        // HTTP → HTTPS redirect on the HTTP port
        let domain_redirect = platform_domain.clone();
        serve_http_redirect(config.http_port, domain_redirect).await
    } else {
        // No TLS — serve plain HTTP (development mode)
        serve_http(config.http_port, routes, platform_domain).await
    }
}

async fn serve_http(port: u16, routes: RoutingTable, domain: Arc<String>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, domain = %domain, "HTTP proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let routes = routes.clone();
        let domain = domain.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy_request(routes.clone(), domain.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "proxy connection error");
            }
        });
    }
}

async fn serve_https(
    port: u16,
    acceptor: TlsAcceptor,
    routes: RoutingTable,
    domain: Arc<String>,
) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, domain = %domain, "HTTPS proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let routes = routes.clone();
        let domain = domain.clone();
        tokio::spawn(async move {
            let tls_stream = match acceptor.accept(stream).await {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, "TLS handshake failed");
                    return;
                }
            };
            let io = TokioIo::new(tls_stream);
            let svc = service_fn(move |req| proxy_request(routes.clone(), domain.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "HTTPS connection error");
            }
        });
    }
}

async fn serve_http_redirect(port: u16, domain: Arc<String>) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "HTTP→HTTPS redirect listening");

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
                let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
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
    routes: RoutingTable,
    platform_domain: Arc<String>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    let hostname = host.split(':').next().unwrap_or("");
    let project_id = extract_project_id(hostname, &platform_domain);

    let backend_ip = {
        let table = routes.read().await;
        table.get(&project_id).cloned()
    };

    let Some(ip) = backend_ip else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .header("Content-Type", "text/plain")
            .body(Full::new(Bytes::from(format!(
                "project not found: '{project_id}'"
            ))))
            .unwrap());
    };

    match forward_request(&ip, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!(project = %project_id, error = %e, "backend request failed");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .header("Content-Type", "text/plain")
                .body(Full::new(Bytes::from("bad gateway")))
                .unwrap())
        }
    }
}

async fn forward_request(
    backend_ip: &str,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>> {
    let uri = format!("http://{}:{}{}", backend_ip, 80, req.uri().path());

    let stream = tokio::net::TcpStream::connect(format!("{backend_ip}:80")).await?;
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(conn);

    let proxy_req = Request::builder()
        .method(req.method())
        .uri(&uri)
        .body(req.into_body())
        .unwrap();

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

fn extract_project_id(hostname: &str, platform_domain: &str) -> String {
    let suffix = format!(".{platform_domain}");

    if let Some(subdomain) = hostname.strip_suffix(&suffix) {
        subdomain
            .strip_prefix("www.")
            .unwrap_or(subdomain)
            .to_string()
    } else {
        hostname.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subdomain_extraction() {
        assert_eq!(extract_project_id("my-app.jkbase.app", "jkbase.app"), "my-app");
        assert_eq!(extract_project_id("www.my-app.jkbase.app", "jkbase.app"), "my-app");
        assert_eq!(extract_project_id("my-app", "jkbase.app"), "my-app");
        assert_eq!(extract_project_id("custom.example.com", "jkbase.app"), "custom.example.com");
        assert_eq!(extract_project_id("my-app.localhost", "localhost"), "my-app");
    }
}
