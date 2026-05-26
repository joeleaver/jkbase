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
use tracing::{error, info};

pub type RoutingTable = Arc<RwLock<HashMap<String, String>>>;

pub fn new_routing_table() -> RoutingTable {
    Arc::new(RwLock::new(HashMap::new()))
}

pub struct ProxyConfig {
    pub port: u16,
    pub platform_domain: String,
}

pub async fn serve(config: ProxyConfig, routes: RoutingTable) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    let listener = TcpListener::bind(addr).await?;
    let platform_domain = Arc::new(config.platform_domain);
    info!(%addr, domain = %platform_domain, "proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let routes = routes.clone();
        let domain = platform_domain.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy_request(routes.clone(), domain.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "proxy connection error");
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

    // Strip port number if present
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
    // project.platform.tld → project
    // www.project.platform.tld → project (strip leading www)
    // bare hostname (no dots, or not matching platform domain) → use as-is
    let suffix = format!(".{platform_domain}");

    if let Some(subdomain) = hostname.strip_suffix(&suffix) {
        // Strip leading "www." if present
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
