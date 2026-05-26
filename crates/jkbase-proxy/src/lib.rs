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

pub async fn serve(port: u16, routes: RoutingTable) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "proxy listening");

    loop {
        let (stream, _peer) = listener.accept().await?;
        let routes = routes.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| proxy_request(routes.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "proxy connection error");
            }
        });
    }
}

async fn proxy_request(
    routes: RoutingTable,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let host = req
        .headers()
        .get("host")
        .and_then(|h| h.to_str().ok())
        .unwrap_or("")
        .split(':')
        .next()
        .unwrap_or("");

    let project_id = extract_project_id(host);

    let backend_ip = {
        let table = routes.read().await;
        table.get(&project_id).cloned()
    };

    let Some(ip) = backend_ip else {
        return Ok(Response::builder()
            .status(StatusCode::NOT_FOUND)
            .body(Full::new(Bytes::from(format!(
                "no project found for host '{host}'"
            ))))
            .unwrap());
    };

    match forward_request(&ip, req).await {
        Ok(resp) => Ok(resp),
        Err(e) => {
            error!(project = %project_id, error = %e, "backend request failed");
            Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
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

fn extract_project_id(host: &str) -> String {
    // For Phase 1: treat the full hostname as the project ID,
    // or extract subdomain from *.jkbase.dev
    if let Some(subdomain) = host.strip_suffix(".jkbase.dev") {
        subdomain.to_string()
    } else {
        host.to_string()
    }
}
