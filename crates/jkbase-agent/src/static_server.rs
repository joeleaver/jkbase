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
    // The image-root fallthrough: block `_`-prefixed top-level entries (host-internal
    // control files). The site variant below does NOT block them.
    serve_static(root, path, true, true).await
}

pub async fn handle_static_with_path(
    root: &Path,
    path: &str,
    spa: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    serve_static(root, path, spa, false).await
}

async fn serve_static(
    root: &Path,
    path: &str,
    spa: bool,
    block_internal: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let request_path = path.trim_start_matches('/');

    let file_path = if request_path.is_empty() {
        root.join("index.html")
    } else {
        root.join(request_path)
    };

    match serve_file(root, &file_path, block_internal).await {
        Ok(resp) => Ok(resp),
        // SPA fallback serves the root index.html, which is never `_`-prefixed.
        Err(_) if spa => match serve_file(root, &root.join("index.html"), block_internal).await {
            Ok(resp) => Ok(resp),
            Err(_) => Ok(not_found()),
        },
        Err(_) => Ok(not_found()),
    }
}

async fn serve_file(
    root: &Path,
    file_path: &Path,
    block_internal: bool,
) -> Result<Response<Full<Bytes>>> {
    let canonical = file_path
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("path error: {e}"))?;

    let root_canonical = root
        .canonicalize()
        .map_err(|e| anyhow::anyhow!("root path error: {e}"))?;

    if !canonical.starts_with(&root_canonical) {
        anyhow::bail!("path traversal attempt");
    }

    // Refuse host-internal control files: check the RESOLVED path's first component
    // under root (defeats `//`, `./`, and `dir/../` normalizations that a raw request
    // string could use to reach a `_`-prefixed root entry).
    if block_internal
        && canonical
            .strip_prefix(&root_canonical)
            .ok()
            .and_then(|rel| rel.components().next())
            .and_then(|c| c.as_os_str().to_str())
            .is_some_and(|seg| seg.starts_with('_'))
    {
        anyhow::bail!("internal control file");
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    async fn status(root: &Path, path: &str, block_internal: bool) -> u16 {
        serve_static(root, path, false, block_internal)
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    #[tokio::test]
    async fn fallthrough_blocks_internal_control_files() {
        let dir = std::env::temp_dir().join(format!("ss-guard-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("_servers")).unwrap();
        fs::create_dir_all(dir.join("assets")).unwrap();
        fs::write(dir.join("_servers/api.json"), r#"{"env":{"SECRET":"x"}}"#).unwrap();
        fs::write(dir.join("_layerpaths.json"), "[]").unwrap();
        fs::write(dir.join("index.html"), "<h1>ok</h1>").unwrap();
        fs::write(dir.join("assets/app.js"), "console.log(1)").unwrap();

        // Internal `_`-prefixed files are blocked at the image-root fallthrough,
        // including via `//`, `./`, and `dir/../` normalizations onto a real path.
        for p in [
            "/_servers/api.json",
            "//_servers/api.json",
            "/./_servers/api.json",
            "/assets/../_servers/api.json",
            "/_layerpaths.json",
        ] {
            assert_eq!(status(&dir, p, true).await, 404, "fallthrough must block {p}");
        }

        // Legit non-internal content is still served.
        assert_eq!(status(&dir, "/assets/app.js", true).await, 200);
        assert_eq!(status(&dir, "/index.html", true).await, 200);

        // Site serving (block_internal=false) keeps `_`-prefixed framework dirs.
        fs::create_dir_all(dir.join("_next")).unwrap();
        fs::write(dir.join("_next/app.js"), "x").unwrap();
        assert_eq!(status(&dir, "/_next/app.js", false).await, 200, "sites allow _next/");
        assert_eq!(status(&dir, "/_next/app.js", true).await, 404, "fallthrough blocks _next/");

        let _ = fs::remove_dir_all(&dir);
    }
}
