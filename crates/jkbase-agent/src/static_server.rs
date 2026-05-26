use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use tokio::net::TcpListener;
use tracing::{error, info};

pub async fn serve(root: PathBuf, port: u16) -> Result<()> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;
    info!(%addr, "listening");

    loop {
        let (stream, peer) = listener.accept().await?;
        let root = root.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle_request(root.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(%peer, error = %e, "connection error");
            }
        });
    }
}

async fn handle_request(
    root: PathBuf,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    let request_path = path.trim_start_matches('/');

    let file_path = if request_path.is_empty() {
        root.join("index.html")
    } else {
        root.join(request_path)
    };

    // Canonicalize and verify the path is within the root
    match serve_file(&root, &file_path).await {
        Ok(resp) => Ok(resp),
        Err(_) => {
            // Try index.html for SPA fallback
            match serve_file(&root, &root.join("index.html")).await {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(not_found()),
            }
        }
    }
}

async fn serve_file(root: &Path, file_path: &Path) -> Result<Response<Full<Bytes>>> {
    let canonical = file_path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("path error: {e}"))?;

    let root_canonical = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("root path error: {e}"))?;

    if !canonical.starts_with(&root_canonical) {
        anyhow::bail!("path traversal attempt");
    }

    if !canonical.is_file() {
        anyhow::bail!("not a file");
    }

    let content = tokio::fs::read(&canonical).await?;
    let mime = guess_mime(&canonical);

    Ok(Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", mime)
        .body(Full::new(Bytes::from(content)))
        .unwrap())
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("404 Not Found")))
        .unwrap()
}

fn guess_mime(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html" | "htm") => "text/html; charset=utf-8",
        Some("css") => "text/css; charset=utf-8",
        Some("js" | "mjs") => "application/javascript; charset=utf-8",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg" | "jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("txt") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        Some("wasm") => "application/wasm",
        Some("pdf") => "application/pdf",
        _ => "application/octet-stream",
    }
}
