use anyhow::Result;
use http_body_util::Full;
use hyper::body::Bytes;
use hyper::{HeaderMap, Request, Response, StatusCode};
use std::path::Path;
use std::time::{Duration, UNIX_EPOCH};
use tokio::io::{AsyncReadExt, AsyncSeekExt};

/// The conditional / range request headers a static GET honors. Cloned out of the
/// request so it can cross the `serve_static` / SPA-fallback boundary cheaply.
#[derive(Default)]
pub struct ReqConds {
    range: Option<String>,
    if_none_match: Option<String>,
    if_modified_since: Option<String>,
}

impl ReqConds {
    pub fn from_headers(h: &HeaderMap) -> Self {
        let get = |name: &str| {
            h.get(name)
                .and_then(|v| v.to_str().ok())
                .map(str::to_string)
        };
        Self {
            range: get("range"),
            if_none_match: get("if-none-match"),
            if_modified_since: get("if-modified-since"),
        }
    }
}

pub async fn handle_static(
    root: &Path,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let conds = ReqConds::from_headers(req.headers());
    let path = req.uri().path();
    // The image-root fallthrough: block `_`-prefixed top-level entries (host-internal
    // control files). The site variant below does NOT block them.
    serve_static(root, path, true, true, &conds).await
}

pub async fn handle_static_with_path(
    root: &Path,
    path: &str,
    spa: bool,
    conds: &ReqConds,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    serve_static(root, path, spa, false, conds).await
}

async fn serve_static(
    root: &Path,
    path: &str,
    spa: bool,
    block_internal: bool,
    conds: &ReqConds,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let request_path = path.trim_start_matches('/');

    let file_path = if request_path.is_empty() {
        root.join("index.html")
    } else {
        root.join(request_path)
    };

    match serve_file(root, &file_path, block_internal, conds).await {
        Ok(resp) => Ok(resp),
        // SPA fallback serves the root index.html (never `_`-prefixed) for a route-like
        // path so client-side routing resolves. A missing path that LOOKS like a build
        // asset (`.wasm`/`.js`/`.css`/…) 404s instead: serving HTML in its place would
        // let a client holding a stale index.html (old asset hash) fetch HTML as
        // wasm/js and break `instantiate`. The fallback is a fresh document, so
        // conditional/range headers meant for the missing asset don't apply — serve it
        // whole.
        Err(_) if spa && !has_asset_extension(Path::new(request_path)) => {
            match serve_file(
                root,
                &root.join("index.html"),
                block_internal,
                &ReqConds::default(),
            )
            .await
            {
                Ok(resp) => Ok(resp),
                Err(_) => Ok(not_found()),
            }
        }
        Err(_) => Ok(not_found()),
    }
}

async fn serve_file(
    root: &Path,
    file_path: &Path,
    block_internal: bool,
    conds: &ReqConds,
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

    let meta = tokio::fs::metadata(&canonical).await?;
    if !meta.is_file() {
        anyhow::bail!("not a file");
    }
    let size = meta.len();
    let mtime = meta
        .modified()
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Cheap validator from mtime+size (no per-request content hash) — the standard
    // static-file etag. Strong form; a rebuild/redeploy changes mtime ⇒ new etag.
    let etag = format!("\"{mtime:x}-{size:x}\"");
    let last_modified = httpdate::fmt_http_date(UNIX_EPOCH + Duration::from_secs(mtime));
    let mime = guess_mime(&canonical);
    // Freshness policy from the resolved name: hashed assets are immutable-forever, HTML
    // must revalidate (pick up redeploys), everything else gets a short max-age. Echoed
    // on 200/206/304 alike so a revalidation carries the same policy a full GET would.
    let cache = cache_control(&canonical);

    // Conditional GET: If-None-Match (precedence) then If-Modified-Since → 304.
    if not_modified(conds, &etag, mtime) {
        return Ok(
            base_headers(StatusCode::NOT_MODIFIED, mime, &etag, &last_modified, cache)
                .body(Full::new(Bytes::new()))
                .unwrap(),
        );
    }

    // Range → 206 (read only the requested slice) / 416.
    if let Some(spec) = &conds.range {
        match parse_range(spec, size) {
            RangeOutcome::Partial { start, end } => {
                let slice = read_slice(&canonical, start, end).await?;
                return Ok(base_headers(
                    StatusCode::PARTIAL_CONTENT,
                    mime,
                    &etag,
                    &last_modified,
                    cache,
                )
                .header("Content-Range", format!("bytes {start}-{end}/{size}"))
                .body(Full::new(Bytes::from(slice)))
                .unwrap());
            }
            RangeOutcome::Unsatisfiable => {
                return Ok(Response::builder()
                    .status(StatusCode::RANGE_NOT_SATISFIABLE)
                    .header("Accept-Ranges", "bytes")
                    .header("Content-Range", format!("bytes */{size}"))
                    .body(Full::new(Bytes::new()))
                    .unwrap());
            }
            RangeOutcome::Full => {}
        }
    }

    let content = tokio::fs::read(&canonical).await?;
    Ok(
        base_headers(StatusCode::OK, mime, &etag, &last_modified, cache)
            .body(Full::new(Bytes::from(content)))
            .unwrap(),
    )
}

/// A response builder carrying the headers every representation shares: Content-Type,
/// the cache validators (ETag, Last-Modified), the freshness policy (`Cache-Control`),
/// and `Accept-Ranges: bytes`.
fn base_headers(
    status: StatusCode,
    mime: &str,
    etag: &str,
    last_modified: &str,
    cache_control: &str,
) -> hyper::http::response::Builder {
    Response::builder()
        .status(status)
        .header("Content-Type", mime)
        .header("ETag", etag)
        .header("Last-Modified", last_modified)
        .header("Cache-Control", cache_control)
        .header("Accept-Ranges", "bytes")
}

/// Read the inclusive byte range `[start, end]` of `path` without buffering the whole
/// file (seek + bounded read).
async fn read_slice(path: &Path, start: u64, end: u64) -> Result<Vec<u8>> {
    let mut f = tokio::fs::File::open(path).await?;
    f.seek(std::io::SeekFrom::Start(start)).await?;
    let len = (end - start + 1) as usize;
    let mut buf = vec![0u8; len];
    f.read_exact(&mut buf).await?;
    Ok(buf)
}

enum RangeOutcome {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
}

/// Parse a single `Range: bytes=…` (see the object store's copy for the RFC 9110
/// semantics): malformed / unknown-unit / multi-range → serve the full 200; a
/// well-formed out-of-bounds range → 416.
fn parse_range(spec: &str, total: u64) -> RangeOutcome {
    let Some(rest) = spec.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    if rest.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((a, b)) = rest.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = match (a.is_empty(), b.is_empty()) {
        (true, false) => match b.parse::<u64>() {
            Ok(0) => return RangeOutcome::Unsatisfiable,
            Ok(_) if total == 0 => return RangeOutcome::Unsatisfiable,
            Ok(n) => (total - n.min(total), total - 1),
            Err(_) => return RangeOutcome::Full,
        },
        (false, true) => match a.parse::<u64>() {
            Ok(start) if start < total => (start, total - 1),
            Ok(_) => return RangeOutcome::Unsatisfiable,
            Err(_) => return RangeOutcome::Full,
        },
        (false, false) => match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(start), Ok(end)) => {
                if start > end || start >= total {
                    return RangeOutcome::Unsatisfiable;
                }
                (start, end.min(total - 1))
            }
            _ => return RangeOutcome::Full,
        },
        (true, true) => return RangeOutcome::Full,
    };
    RangeOutcome::Partial { start, end }
}

/// RFC 9110 conditional GET: If-None-Match (weak compare) takes precedence over
/// If-Modified-Since. `true` ⇒ respond 304.
fn not_modified(conds: &ReqConds, etag: &str, mtime: u64) -> bool {
    if let Some(inm) = &conds.if_none_match {
        let ours = etag.trim_matches('"');
        return inm.split(',').any(|t| {
            let t = t.trim();
            t == "*" || t.strip_prefix("W/").unwrap_or(t).trim_matches('"') == ours
        });
    }
    if let Some(ims) = &conds.if_modified_since
        && let Ok(t) = httpdate::parse_http_date(ims)
        && let Ok(since) = t.duration_since(UNIX_EPOCH)
    {
        return mtime <= since.as_secs();
    }
    false
}

fn not_found() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .body(Full::new(Bytes::from("404 Not Found")))
        .unwrap()
}

/// Freshness policy for a resolved file, keyed off its name (no config, no I/O):
/// - `*.html`/`*.htm` → `no-cache` (must revalidate every load so a redeploy is picked
///   up; the ETag machinery makes that a cheap 304). Also covers the SPA-fallback
///   index.html, which resolves here.
/// - a build-fingerprinted asset (`is_fingerprinted`) → `immutable`, cached ~forever:
///   the content hash IS the version, so the byte stream never changes under that name.
///   This is THE fix for the "11 MB wasm re-downloaded every load" report.
/// - anything else → a short `max-age`; still revalidates via ETag/Last-Modified once
///   stale, so an overwrite is picked up within the window.
fn cache_control(path: &Path) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html" | "htm") => "no-cache",
        _ if is_fingerprinted(path) => "public, max-age=31536000, immutable",
        _ => "public, max-age=3600",
    }
}

/// Heuristic: does this file name carry a build content-hash segment? Splits the stem
/// (name minus final extension) on `-`, `.`, `_` and matches any 8–64 char ASCII-hex
/// run. Covers trunk (`app-8f3a2b1c_bg.wasm`, `app-<hex>.js/.css`; splitting `_` peels
/// wasm-bindgen's `_bg`), Vite (`index.4e2f8a91.js`), and webpack `[contenthash:8+]`.
/// A hand-named `index.html` / `logo.png` / `main.js` has no such segment.
fn is_fingerprinted(path: &Path) -> bool {
    let Some(stem) = path.file_stem().and_then(|s| s.to_str()) else {
        return false;
    };
    stem.split(['-', '.', '_'])
        .any(|seg| (8..=64).contains(&seg.len()) && seg.bytes().all(|b| b.is_ascii_hexdigit()))
}

/// Does the request path name a build asset (a known non-HTML content extension)?
/// Used to suppress the SPA index.html fallback for a missing asset — serving HTML as
/// `application/wasm`/`javascript` breaks the client. HTML/dotless/unknown extensions
/// stay eligible for the fallback (real client-side routes).
fn has_asset_extension(path: &Path) -> bool {
    matches!(
        path.extension().and_then(|e| e.to_str()),
        Some(
            "js" | "mjs"
                | "wasm"
                | "css"
                | "json"
                | "png"
                | "jpg"
                | "jpeg"
                | "gif"
                | "svg"
                | "ico"
                | "woff"
                | "woff2"
                | "ttf"
                | "txt"
                | "xml"
                | "pdf"
                | "map"
        )
    )
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
    use http_body_util::BodyExt;
    use std::fs;

    async fn status(root: &Path, path: &str, block_internal: bool) -> u16 {
        serve_static(root, path, false, block_internal, &ReqConds::default())
            .await
            .unwrap()
            .status()
            .as_u16()
    }

    async fn serve_conds(root: &Path, path: &str, conds: ReqConds) -> (u16, HeaderMap, Vec<u8>) {
        let resp = serve_static(root, path, false, false, &conds)
            .await
            .unwrap();
        let status = resp.status().as_u16();
        let headers = resp.headers().clone();
        let body = resp
            .into_body()
            .collect()
            .await
            .unwrap()
            .to_bytes()
            .to_vec();
        (status, headers, body)
    }

    #[tokio::test]
    async fn static_range_conditional_and_validators() {
        let dir = std::env::temp_dir().join(format!("ss-range-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("data.bin"), b"0123456789").unwrap();

        // Full GET: 200 + validators + Accept-Ranges.
        let (st, h, body) = serve_conds(&dir, "/data.bin", ReqConds::default()).await;
        assert_eq!(st, 200);
        assert_eq!(h.get("accept-ranges").unwrap(), "bytes");
        assert!(h.get("etag").is_some());
        assert!(h.get("last-modified").is_some());
        assert_eq!(body, b"0123456789");
        let etag = h.get("etag").unwrap().to_str().unwrap().to_string();

        // Range: 206 + Content-Range + slice.
        let (st, h, body) = serve_conds(
            &dir,
            "/data.bin",
            ReqConds {
                range: Some("bytes=2-5".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 206);
        assert_eq!(h.get("content-range").unwrap(), "bytes 2-5/10");
        assert_eq!(body, b"2345");

        // Suffix range.
        let (st, _, body) = serve_conds(
            &dir,
            "/data.bin",
            ReqConds {
                range: Some("bytes=-3".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 206);
        assert_eq!(body, b"789");

        // Unsatisfiable: 416 + bytes */10.
        let (st, h, _) = serve_conds(
            &dir,
            "/data.bin",
            ReqConds {
                range: Some("bytes=100-200".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 416);
        assert_eq!(h.get("content-range").unwrap(), "bytes */10");

        // If-None-Match with the current etag: 304, empty body.
        let (st, _, body) = serve_conds(
            &dir,
            "/data.bin",
            ReqConds {
                if_none_match: Some(etag),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 304);
        assert!(body.is_empty());

        let _ = fs::remove_dir_all(&dir);
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
            assert_eq!(
                status(&dir, p, true).await,
                404,
                "fallthrough must block {p}"
            );
        }

        // Legit non-internal content is still served.
        assert_eq!(status(&dir, "/assets/app.js", true).await, 200);
        assert_eq!(status(&dir, "/index.html", true).await, 200);

        // Site serving (block_internal=false) keeps `_`-prefixed framework dirs.
        fs::create_dir_all(dir.join("_next")).unwrap();
        fs::write(dir.join("_next/app.js"), "x").unwrap();
        assert_eq!(
            status(&dir, "/_next/app.js", false).await,
            200,
            "sites allow _next/"
        );
        assert_eq!(
            status(&dir, "/_next/app.js", true).await,
            404,
            "fallthrough blocks _next/"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn cache_control_by_asset_class() {
        let dir = std::env::temp_dir().join(format!("ss-cache-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), "<h1>ok</h1>").unwrap();
        fs::write(dir.join("app-8f3a2b1c_bg.wasm"), b"\0asm").unwrap();
        fs::write(dir.join("index.4e2f8a91.js"), "x").unwrap();
        fs::write(dir.join("logo.png"), b"png").unwrap();

        let cc = |h: &HeaderMap| {
            h.get("cache-control")
                .unwrap()
                .to_str()
                .unwrap()
                .to_string()
        };

        // HTML must revalidate so redeploys are seen.
        let (_, h, _) = serve_conds(&dir, "/index.html", ReqConds::default()).await;
        assert_eq!(cc(&h), "no-cache");

        // Fingerprinted assets are immutable-forever (trunk wasm + Vite js).
        let (_, h, _) = serve_conds(&dir, "/app-8f3a2b1c_bg.wasm", ReqConds::default()).await;
        assert_eq!(cc(&h), "public, max-age=31536000, immutable");
        let (_, h, _) = serve_conds(&dir, "/index.4e2f8a91.js", ReqConds::default()).await;
        assert_eq!(cc(&h), "public, max-age=31536000, immutable");

        // Un-hashed asset → short max-age (still ETag-revalidated once stale).
        let (_, h, _) = serve_conds(&dir, "/logo.png", ReqConds::default()).await;
        assert_eq!(cc(&h), "public, max-age=3600");

        // The policy rides 206 (Range) and 304 (conditional) responses too.
        let (st, h, _) = serve_conds(
            &dir,
            "/app-8f3a2b1c_bg.wasm",
            ReqConds {
                range: Some("bytes=0-1".into()),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 206);
        assert_eq!(cc(&h), "public, max-age=31536000, immutable");

        let (_, h, _) = serve_conds(&dir, "/index.html", ReqConds::default()).await;
        let etag = h.get("etag").unwrap().to_str().unwrap().to_string();
        let (st, h, _) = serve_conds(
            &dir,
            "/index.html",
            ReqConds {
                if_none_match: Some(etag),
                ..Default::default()
            },
        )
        .await;
        assert_eq!(st, 304);
        assert_eq!(cc(&h), "no-cache");

        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn spa_fallback_only_for_route_like_paths() {
        let dir = std::env::temp_dir().join(format!("ss-spa-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("index.html"), "<h1>app</h1>").unwrap();

        // Missing route-like path → SPA fallback serves index.html (no-cache).
        let resp = serve_static(
            &dir,
            "/some/client/route",
            true,
            false,
            &ReqConds::default(),
        )
        .await
        .unwrap();
        assert_eq!(resp.status().as_u16(), 200);
        assert_eq!(resp.headers().get("cache-control").unwrap(), "no-cache");
        assert_eq!(
            resp.headers().get("content-type").unwrap(),
            "text/html; charset=utf-8"
        );

        // Missing hashed asset → 404, NOT index.html served as wasm.
        for missing in [
            "/app-deadbeef_bg.wasm",
            "/app-deadbeef.js",
            "/style-deadbeef.css",
        ] {
            let resp = serve_static(&dir, missing, true, false, &ReqConds::default())
                .await
                .unwrap();
            assert_eq!(
                resp.status().as_u16(),
                404,
                "asset {missing} must 404, not SPA-fallback"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn fingerprint_detection() {
        for name in [
            "pw-studio-web-8f3a2b1c_bg.wasm",
            "app-8f3a2b1c.js",
            "index.4e2f8a91.js",
            "style.0a1b2c3d4e5f6789.css",
        ] {
            assert!(is_fingerprinted(Path::new(name)), "{name} should be hashed");
        }
        for name in [
            "index.html",
            "main.js",
            "logo.png",
            "robots.txt",
            "app-1234.js",
        ] {
            assert!(
                !is_fingerprinted(Path::new(name)),
                "{name} should NOT be hashed"
            );
        }
    }
}
