use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{Request, Response, StatusCode};
use std::path::Path;

pub async fn handle_static(
    root: &Path,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path();
    handle_static_with_path(root, path, true).await
}

pub async fn handle_static_with_path(
    root: &Path,
    path: &str,
    spa: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let request_path = path.trim_start_matches('/');

    let file_path = if request_path.is_empty() {
        root.join("index.html")
    } else {
        root.join(request_path)
    };

    match serve_file(root, &file_path).await {
        Ok(resp) => Ok(resp),
        Err(_) if spa => match serve_file(root, &root.join("index.html")).await {
            Ok(resp) => Ok(resp),
            Err(_) => Ok(not_found()),
        },
        Err(_) => Ok(not_found()),
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
