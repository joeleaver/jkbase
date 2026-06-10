//! `mirror` — the cross-tenant package MIRROR: a TLS-terminating, content-addressed
//! cache for package registries. This is the P0-1 SSRF/exfil engine and the
//! cross-tenant dedup point (one upstream fetch per unique artifact, served to every
//! tenant from a shared store).
//!
//! ## The only byte path
//!
//! Every request is **classify → serve-from-store, or on a miss: fetch the
//! SSRF-pinned upstream into a temp file, re-hash, store (content-addressed), then
//! serve**. There is never an upstream-socket → tenant-socket splice — the mirror
//! only ever emits bytes it has already written to its own store and verified the
//! hash of. This makes the cross-tenant guarantees structural:
//!
//!  1. Tenants can't write the store — build VMs are HTTP clients of this proxy;
//!     only host code ([`MirrorTls`]) writes blobs.
//!  2. The platform writes only content-verified real-upstream bytes — the upstream
//!     leg validates the REAL registry cert against public webpki roots (reqwest's
//!     default root store, NOT our build CA) and dials only the pre-pinned public IP
//!     handed down from the egress SSRF gate (no re-resolve — invariant I-5).
//!  3. Content-addressing forbids aliasing — a blob is stored under `sha256(bytes)`,
//!     and `put_if_absent` never overwrites; you cannot store bytes X under name
//!     sha256(Y). This is the P0-2 cache-key-safety fix.
//!  4. Each tenant's build tool re-verifies every byte against ITS OWN lockfile
//!     (cargo vs Cargo.lock, npm vs package-lock integrity, pip --require-hashes) —
//!     so the mirror is untrusted-by-tool; a wrong/poisoned entry fails only the
//!     build whose lockfile rejects it, and is inert to everyone else.
//!
//! Only independently-verifiable artifacts are cached (tarballs / wheels / sdists /
//! .crate / registry index). Never opaque compiled output (that stays per-project on
//! the cache-drive).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use jkbase_substrate::{BlobStore, LocalFsBlobStore};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::Mutex;
use tokio_rustls::TlsAcceptor;

use crate::build_ca::CertSigner;

/// Max request-head size we will buffer (request line + headers).
const MAX_REQ_HEAD: usize = 16 * 1024;
/// Max size of a single cached 200 artifact body.
const MAX_ARTIFACT_BYTES: u64 = 4 * 1024 * 1024 * 1024;
/// Max body we will buffer+relay for a non-200 upstream response (error pages, etc).
const MAX_RELAY_BODY: usize = 1024 * 1024;
/// Freshness window for mutable registry index/metadata. Immutable artifacts never
/// expire. Mutable entries are NOT security-load-bearing — worst case a build sees a
/// slightly stale index and fails resolution (and the tenant lockfile still gates).
const INDEX_TTL: Duration = Duration::from_secs(300);
/// Upstream fetch ceilings.
const UPSTREAM_CONNECT_TIMEOUT: Duration = Duration::from_secs(30);
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(300);
/// Per-request idle read timeout on a kept-alive MITM connection.
const REQUEST_READ_TIMEOUT: Duration = Duration::from_secs(120);

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Class {
    /// Versioned, immutable artifact — cache permanently.
    Immutable,
    /// Mutable registry index/metadata — cache with a short TTL.
    Mutable,
    /// Not a recognizable cacheable path on a mirror host — fetch + serve, no store.
    Disallowed,
}

/// Classify a `(host, path)` into a cache policy. Conservative: only well-known
/// immutable shapes are cached permanently; anything ambiguous is treated as mutable
/// (a needless revalidation is harmless; serving stale mutable data forever is not).
fn classify(host: &str, path: &str) -> Class {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    match h.as_str() {
        // crates.io: static = immutable .crate tarballs; index = sparse index (mutable).
        "static.crates.io" => Class::Immutable,
        "index.crates.io" => Class::Mutable,
        // npm: /<pkg>/-/<pkg>-<ver>.tgz is the immutable tarball; /<pkg> is the packument.
        "registry.npmjs.org" => {
            if path.contains("/-/") && path.ends_with(".tgz") {
                Class::Immutable
            } else {
                Class::Mutable
            }
        }
        // PyPI: files.pythonhosted.org serves immutable wheels/sdists; pypi.org/simple is index.
        "files.pythonhosted.org" => Class::Immutable,
        "pypi.org" => Class::Mutable,
        _ => Class::Disallowed,
    }
}

// ---------------------------------------------------------------------------
// On-disk index
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
struct IndexEntry {
    /// hex sha256 of the cached body.
    digest: String,
    content_type: Option<String>,
    content_encoding: Option<String>,
    /// Permanent when true; TTL-revalidated when false.
    immutable: bool,
    /// Unix seconds when this entry was fetched.
    fetched_at: u64,
}

impl IndexEntry {
    fn fresh(&self) -> bool {
        if self.immutable {
            return true;
        }
        let age = now_unix().saturating_sub(self.fetched_at);
        age < INDEX_TTL.as_secs()
    }
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// HTTP request parsing (strict, body-free)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedReq {
    method: String,
    path: String,
    host: Option<String>,
    keep_alive: bool,
    /// True if the request announces a body (Content-Length / Transfer-Encoding).
    /// We reject these — registry fetches are body-free GET/HEAD, and refusing bodies
    /// sidesteps request-smuggling entirely.
    has_body: bool,
}

/// Parse a buffered HTTP/1.x request head (everything up to and excluding the final
/// CRLFCRLF). Returns `None` on a malformed start line.
fn parse_request_head(head: &[u8]) -> Option<ParsedReq> {
    let text = std::str::from_utf8(head).ok()?;
    let mut lines = text.split("\r\n");
    let start = lines.next()?;
    let mut parts = start.split(' ');
    let method = parts.next()?.to_string();
    let path = parts.next()?.to_string();
    let version = parts.next()?; // e.g. HTTP/1.1
    if method.is_empty() || path.is_empty() || !version.starts_with("HTTP/") {
        return None;
    }
    // HTTP/1.1 defaults to keep-alive; HTTP/1.0 defaults to close.
    let mut keep_alive = version == "HTTP/1.1";
    let mut host = None;
    let mut has_body = false;
    for line in lines {
        if line.is_empty() {
            continue;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let name = name.trim().to_ascii_lowercase();
        let value = value.trim();
        match name.as_str() {
            "host" => host = Some(value.to_ascii_lowercase()),
            "connection" => {
                if value.eq_ignore_ascii_case("close") {
                    keep_alive = false;
                } else if value.eq_ignore_ascii_case("keep-alive") {
                    keep_alive = true;
                }
            }
            "content-length" if value.parse::<u64>().unwrap_or(0) > 0 => has_body = true,
            "transfer-encoding" => has_body = true,
            _ => {}
        }
    }
    Some(ParsedReq {
        method,
        path,
        host,
        keep_alive,
        has_body,
    })
}

// ---------------------------------------------------------------------------
// Response model + writer
// ---------------------------------------------------------------------------

enum ServeBody {
    /// Stream this on-disk blob (known length).
    File { path: PathBuf, len: u64 },
    /// Inline bytes (relayed non-200 bodies; small error responses).
    Bytes(Vec<u8>),
}

struct MirrorResponse {
    status: u16,
    content_type: Option<String>,
    content_encoding: Option<String>,
    /// Extra response headers to pass through (e.g. `Location` on a 3xx relay).
    extra: Vec<(String, String)>,
    body: ServeBody,
}

impl MirrorResponse {
    fn error(status: u16, msg: &str) -> Self {
        Self {
            status,
            content_type: Some("text/plain; charset=utf-8".to_string()),
            content_encoding: None,
            extra: Vec::new(),
            body: ServeBody::Bytes(msg.as_bytes().to_vec()),
        }
    }
}

fn reason_phrase(status: u16) -> &'static str {
    match status {
        200 => "OK",
        301 => "Moved Permanently",
        302 => "Found",
        303 => "See Other",
        304 => "Not Modified",
        307 => "Temporary Redirect",
        308 => "Permanent Redirect",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        421 => "Misdirected Request",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        504 => "Gateway Timeout",
        _ => "OK",
    }
}

/// Write a full HTTP/1.1 response (status line + headers + Content-Length-framed body)
/// to `w`. `head_only` suppresses the body (HEAD). Always emits Content-Length, so the
/// connection stays framed and keep-alive-safe.
async fn write_response<W: AsyncWrite + Unpin>(
    w: &mut W,
    resp: MirrorResponse,
    head_only: bool,
    keep_alive: bool,
) -> std::io::Result<()> {
    let len = match &resp.body {
        ServeBody::File { len, .. } => *len,
        ServeBody::Bytes(b) => b.len() as u64,
    };
    let mut head = String::with_capacity(256);
    head.push_str(&format!(
        "HTTP/1.1 {} {}\r\n",
        resp.status,
        reason_phrase(resp.status)
    ));
    head.push_str(&format!("Content-Length: {len}\r\n"));
    if let Some(ct) = &resp.content_type {
        head.push_str(&format!("Content-Type: {ct}\r\n"));
    }
    if let Some(ce) = &resp.content_encoding {
        head.push_str(&format!("Content-Encoding: {ce}\r\n"));
    }
    for (k, v) in &resp.extra {
        head.push_str(&format!("{k}: {v}\r\n"));
    }
    head.push_str(if keep_alive {
        "Connection: keep-alive\r\n"
    } else {
        "Connection: close\r\n"
    });
    head.push_str("\r\n");
    w.write_all(head.as_bytes()).await?;

    if head_only {
        return w.flush().await;
    }
    match resp.body {
        ServeBody::Bytes(b) => w.write_all(&b).await?,
        ServeBody::File { path, .. } => {
            let mut f = tokio::fs::File::open(&path).await?;
            tokio::io::copy(&mut f, w).await?;
        }
    }
    w.flush().await
}

// ---------------------------------------------------------------------------
// MirrorTls — the shared mirror handle
// ---------------------------------------------------------------------------

/// The shared package mirror: TLS server config (per-SNI leaves), a content-addressed
/// blob store, an on-disk URL→entry index, and a keyed in-flight lock so concurrent
/// misses of the same URL collapse to one upstream fetch. Cheap to clone behind `Arc`.
pub struct MirrorTls {
    acceptor: TlsAcceptor,
    store: LocalFsBlobStore,
    /// Root of the content store ({data_dir}/buildmirror); `blobs/` and `index/` live
    /// under it. We compute blob read paths directly (local-fs layout) to stream a hit
    /// without a copy.
    root: PathBuf,
    /// Per-URL-key in-flight fetch locks (collapse duplicate concurrent misses).
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
    /// Cache hits served from the store (cross-tenant dedup wins).
    hits: std::sync::atomic::AtomicU64,
    /// Upstream fetches issued (cache misses). hit-rate = hits / (hits + fetches).
    upstream_fetches: std::sync::atomic::AtomicU64,
}

impl MirrorTls {
    /// Build the mirror rooted at `{data_dir}/buildmirror`, using `signer` for per-SNI
    /// leaf certs.
    pub fn new(data_dir: &Path, signer: Arc<CertSigner>) -> Result<Arc<Self>> {
        let root = data_dir.join("buildmirror");
        let store = LocalFsBlobStore::open(root.join("blobs"))
            .map_err(|e| anyhow::anyhow!("open mirror blob store: {e}"))?;
        std::fs::create_dir_all(root.join("index")).context("create mirror index dir")?;
        let acceptor = TlsAcceptor::from(signer.into_server_config());
        Ok(Arc::new(Self {
            acceptor,
            store,
            root,
            locks: Mutex::new(HashMap::new()),
            hits: std::sync::atomic::AtomicU64::new(0),
            upstream_fetches: std::sync::atomic::AtomicU64::new(0),
        }))
    }

    /// `(hits, upstream_fetches)` — the cross-tenant dedup counters. hit-rate is
    /// `hits / (hits + upstream_fetches)`.
    pub fn stats(&self) -> (u64, u64) {
        use std::sync::atomic::Ordering::Relaxed;
        (self.hits.load(Relaxed), self.upstream_fetches.load(Relaxed))
    }

    /// Handle one MITM'd CONNECT: terminate TLS with a leaf for `host`, then serve a
    /// keep-alive loop of registry requests. `addr` is the SSRF-pinned upstream the
    /// egress gate already vetted — the upstream leg dials EXACTLY this (I-5). Consumes
    /// `client`; logs and drops the connection on any error.
    pub async fn handle_mitm(self: Arc<Self>, client: TcpStream, host: String, addr: SocketAddr) {
        let tls = match self.acceptor.accept(client).await {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!(%host, error = %e, "mirror TLS accept failed");
                return;
            }
        };
        // Per-connection upstream client, pinned to the gate-vetted addr. One host per
        // CONNECT, so this is reused across all keep-alive requests on the connection.
        let upstream = match self.upstream_client(&host, addr) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!(%host, error = %e, "mirror upstream client build failed");
                return;
            }
        };
        let mut tls = tls;
        let result = self.serve_requests(&mut tls, host.clone(), &upstream).await;
        // Send TLS close_notify so the client sees a clean EOF, not a truncation error.
        let _ = tls.shutdown().await;
        if let Err(e) = result {
            tracing::debug!(%host, error = %e, "mirror connection ended");
        }
        let (hits, fetches) = self.stats();
        tracing::debug!(%host, hits, upstream_fetches = fetches, "mirror connection closed");
    }

    async fn serve_requests<S>(
        &self,
        tls: &mut S,
        host: String,
        upstream: &reqwest::Client,
    ) -> Result<()>
    where
        S: AsyncReadExt + AsyncWrite + Unpin,
    {
        let host = host.as_str();
        loop {
            let head = match tokio::time::timeout(REQUEST_READ_TIMEOUT, read_head(&mut *tls)).await {
                Ok(Ok(Some(h))) => h,
                Ok(Ok(None)) => return Ok(()), // clean EOF
                Ok(Err(e)) => return Err(e),
                Err(_) => return Ok(()), // idle timeout
            };
            let Some(req) = parse_request_head(&head) else {
                let _ = write_response(
                    &mut *tls,
                    MirrorResponse::error(400, "bad request"),
                    false,
                    false,
                )
                .await;
                return Ok(());
            };

            let head_only = req.method.eq_ignore_ascii_case("HEAD");
            let is_get = req.method.eq_ignore_ascii_case("GET");
            // Strict gate: only body-free GET/HEAD, and the Host must match the
            // CONNECT authority/SNI we vetted+pinned (no host confusion across the
            // pinned tunnel).
            let host_ok = req
                .host
                .as_deref()
                .map(|h| h.trim_end_matches('.').eq_ignore_ascii_case(host))
                .unwrap_or(false);
            let resp = if req.has_body || (!is_get && !head_only) {
                Some(MirrorResponse::error(405, "method not allowed"))
            } else if !host_ok {
                Some(MirrorResponse::error(421, "misdirected request"))
            } else {
                None
            };
            if let Some(r) = resp {
                let ka = req.keep_alive && r.status != 421;
                write_response(&mut *tls, r, head_only, ka).await?;
                if !ka {
                    return Ok(());
                }
                continue;
            }

            let response = match self.get_or_fetch(host, &req.path, upstream).await {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(%host, path = %req.path, error = %e, "mirror fetch failed");
                    MirrorResponse::error(502, "mirror upstream error")
                }
            };
            let keep_alive = req.keep_alive;
            write_response(&mut *tls, response, head_only, keep_alive).await?;
            if !keep_alive {
                return Ok(());
            }
        }
    }

    /// Serve a request: store hit, or miss → fetch-pinned → verify → store → serve.
    async fn get_or_fetch(
        &self,
        host: &str,
        path: &str,
        upstream: &reqwest::Client,
    ) -> Result<MirrorResponse> {
        let class = classify(host, path);
        let canon = format!("{host}{path}");
        let url_key = sha256_hex_str(canon.as_bytes());

        // Fast path: a fresh cached entry whose blob still exists.
        if let Some(hit) = self.try_hit(&url_key).await? {
            return Ok(hit);
        }

        // Miss: collapse concurrent same-URL fetches behind a keyed lock.
        let lock = self.lock_for(&url_key).await;
        let _g = lock.lock().await;
        // Re-check under the lock — another task may have just filled it.
        if let Some(hit) = self.try_hit(&url_key).await? {
            return Ok(hit);
        }

        let fetched = self.fetch_pinned(upstream, host, path).await?;
        match fetched {
            Fetched::Artifact {
                tmp,
                digest,
                content_type,
                content_encoding,
            } => {
                let digest_key = digest_key(&digest);
                // Atomic, content-addressed, dedup-on-name: never overwrites.
                self.store
                    .put_if_absent_file(&digest_key, &tmp)
                    .await
                    .map_err(|e| anyhow::anyhow!("store blob: {e}"))?;
                let _ = tokio::fs::remove_file(&tmp).await;
                if class != Class::Disallowed {
                    let entry = IndexEntry {
                        digest: digest.clone(),
                        content_type: content_type.clone(),
                        content_encoding: content_encoding.clone(),
                        immutable: class == Class::Immutable,
                        fetched_at: now_unix(),
                    };
                    self.write_index(&url_key, &entry).await?;
                }
                let (path, len) = self.blob_path_len(&digest_key).await?;
                Ok(MirrorResponse {
                    status: 200,
                    content_type,
                    content_encoding,
                    extra: Vec::new(),
                    body: ServeBody::File { path, len },
                })
            }
            Fetched::Relay {
                status,
                content_type,
                location,
                body,
            } => {
                // Non-200 (404/403/3xx/...) is relayed, never cached. A 3xx Location is
                // handed back so the client re-issues a fresh, re-gated CONNECT — we
                // never auto-follow off-allowlist (I-6).
                let mut extra = Vec::new();
                if let Some(loc) = location {
                    extra.push(("Location".to_string(), loc));
                }
                Ok(MirrorResponse {
                    status,
                    content_type,
                    content_encoding: None,
                    extra,
                    body: ServeBody::Bytes(body),
                })
            }
        }
    }

    /// A cache hit if the index entry exists, is fresh, was a 200, and its blob is
    /// still on disk.
    async fn try_hit(&self, url_key: &str) -> Result<Option<MirrorResponse>> {
        let Some(entry) = self.read_index(url_key).await? else {
            return Ok(None);
        };
        if !entry.fresh() {
            return Ok(None);
        }
        let digest_key = digest_key(&entry.digest);
        match self.blob_path_len(&digest_key).await {
            Ok((path, len)) => {
                self.hits
                    .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                Ok(Some(MirrorResponse {
                    status: 200,
                    content_type: entry.content_type,
                    content_encoding: entry.content_encoding,
                    extra: Vec::new(),
                    body: ServeBody::File { path, len },
                }))
            }
            Err(_) => Ok(None), // index points at an evicted blob — treat as miss
        }
    }

    /// Build the per-connection upstream client: pinned to the vetted `addr`, no proxy,
    /// HTTPS-only, no auto-redirect, validating the REAL cert vs public webpki roots.
    fn upstream_client(&self, host: &str, addr: SocketAddr) -> Result<reqwest::Client> {
        reqwest::Client::builder()
            .no_proxy()
            .https_only(true)
            .redirect(reqwest::redirect::Policy::none())
            .resolve(host, addr)
            .connect_timeout(UPSTREAM_CONNECT_TIMEOUT)
            .timeout(UPSTREAM_TIMEOUT)
            .user_agent("jkbase-build-mirror")
            .build()
            .context("build upstream client")
    }

    /// Fetch `https://{host}{path}` through the pinned client. On 200, stream the body
    /// to a temp file under the store and hash it as we go. On any other status, buffer
    /// a bounded body to relay.
    async fn fetch_pinned(
        &self,
        upstream: &reqwest::Client,
        host: &str,
        path: &str,
    ) -> Result<Fetched> {
        let url = format!("https://{host}{path}");
        self.upstream_fetches
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let mut resp = upstream.get(&url).send().await.context("upstream send")?;
        let status = resp.status().as_u16();
        let content_type = header_str(&resp, reqwest::header::CONTENT_TYPE);
        let content_encoding = header_str(&resp, reqwest::header::CONTENT_ENCODING);

        if status == 200 {
            let tmp = self.tmp_path();
            if let Some(parent) = tmp.parent() {
                tokio::fs::create_dir_all(parent).await?;
            }
            let mut f = tokio::fs::File::create(&tmp).await?;
            let mut hasher = Sha256::new();
            let mut total: u64 = 0;
            while let Some(chunk) = resp.chunk().await.context("upstream body")? {
                total += chunk.len() as u64;
                if total > MAX_ARTIFACT_BYTES {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    bail!("artifact exceeds {MAX_ARTIFACT_BYTES} bytes");
                }
                hasher.update(&chunk);
                f.write_all(&chunk).await?;
            }
            f.sync_all().await?;
            let digest = hex_of(hasher.finalize());
            Ok(Fetched::Artifact {
                tmp,
                digest,
                content_type,
                content_encoding,
            })
        } else {
            let location = header_str(&resp, reqwest::header::LOCATION);
            let mut body = Vec::new();
            while let Some(chunk) = resp.chunk().await.context("upstream body")? {
                if body.len() + chunk.len() > MAX_RELAY_BODY {
                    body.extend_from_slice(&chunk[..MAX_RELAY_BODY.saturating_sub(body.len())]);
                    break;
                }
                body.extend_from_slice(&chunk);
            }
            Ok(Fetched::Relay {
                status,
                content_type,
                location,
                body,
            })
        }
    }

    // ---- store path helpers ----

    fn tmp_path(&self) -> PathBuf {
        let n = now_unix();
        let pid = std::process::id();
        let uniq = TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        self.root.join("tmp").join(format!("dl.{pid}.{n}.{uniq}"))
    }

    /// Absolute path + length of a stored blob; errs if absent.
    async fn blob_path_len(&self, digest_key: &str) -> Result<(PathBuf, u64)> {
        let path = self.root.join("blobs").join(digest_key);
        let md = tokio::fs::metadata(&path)
            .await
            .with_context(|| format!("stat blob {}", path.display()))?;
        Ok((path, md.len()))
    }

    fn index_path(&self, url_key: &str) -> PathBuf {
        self.root
            .join("index")
            .join(&url_key[..2])
            .join(url_key)
    }

    async fn read_index(&self, url_key: &str) -> Result<Option<IndexEntry>> {
        match tokio::fs::read(self.index_path(url_key)).await {
            Ok(bytes) => Ok(Some(
                serde_json::from_slice(&bytes).context("parse index entry")?,
            )),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    async fn write_index(&self, url_key: &str, entry: &IndexEntry) -> Result<()> {
        let path = self.index_path(url_key);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let bytes = serde_json::to_vec(entry).context("serialize index entry")?;
        let tmp = path.with_extension(format!(
            "tmp.{}.{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        tokio::fs::write(&tmp, &bytes).await?;
        tokio::fs::rename(&tmp, &path).await?; // atomic publish
        Ok(())
    }

    async fn lock_for(&self, url_key: &str) -> Arc<Mutex<()>> {
        let mut map = self.locks.lock().await;
        map.entry(url_key.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }
}

static TMP_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

/// Outcome of an upstream fetch.
enum Fetched {
    Artifact {
        tmp: PathBuf,
        digest: String,
        content_type: Option<String>,
        content_encoding: Option<String>,
    },
    Relay {
        status: u16,
        content_type: Option<String>,
        location: Option<String>,
        body: Vec<u8>,
    },
}

/// Content-address blob key: `<aa>/<hex>` (2-char fan-out).
fn digest_key(digest: &str) -> String {
    format!("{}/{}", &digest[..2], digest)
}

fn header_str(resp: &reqwest::Response, name: reqwest::header::HeaderName) -> Option<String> {
    resp.headers()
        .get(&name)
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
}

fn hex_of(out: impl AsRef<[u8]>) -> String {
    use std::fmt::Write;
    let mut s = String::with_capacity(64);
    for b in out.as_ref() {
        let _ = write!(s, "{b:02x}");
    }
    s
}

fn sha256_hex_str(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex_of(h.finalize())
}

/// Read an HTTP request head (through the terminating CRLFCRLF) from `r`, bounded by
/// [`MAX_REQ_HEAD`]. Returns `Ok(None)` on a clean EOF before any bytes.
async fn read_head<R: AsyncReadExt + Unpin>(r: &mut R) -> Result<Option<Vec<u8>>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = r.read(&mut byte).await?;
        if n == 0 {
            if buf.is_empty() {
                return Ok(None);
            }
            bail!("connection closed mid-request");
        }
        buf.push(byte[0]);
        if buf.len() > MAX_REQ_HEAD {
            bail!("request head too large");
        }
        if buf.ends_with(b"\r\n\r\n") {
            // Trim the trailing CRLFCRLF; parser works on header lines only.
            buf.truncate(buf.len() - 4);
            return Ok(Some(buf));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classify_immutable_vs_mutable() {
        assert_eq!(
            classify("static.crates.io", "/serde/serde-1.0.0.crate"),
            Class::Immutable
        );
        assert_eq!(classify("index.crates.io", "/se/rd/serde"), Class::Mutable);
        assert_eq!(
            classify("registry.npmjs.org", "/lodash/-/lodash-4.17.21.tgz"),
            Class::Immutable
        );
        assert_eq!(classify("registry.npmjs.org", "/lodash"), Class::Mutable);
        assert_eq!(
            classify("files.pythonhosted.org", "/packages/aa/bb/x-1.0-py3.whl"),
            Class::Immutable
        );
        assert_eq!(classify("pypi.org", "/simple/flask/"), Class::Mutable);
        assert_eq!(classify("example.com", "/x"), Class::Disallowed);
    }

    #[test]
    fn digest_key_shards() {
        let d = "abcd1234".to_string() + &"0".repeat(56);
        assert_eq!(digest_key(&d), format!("ab/{d}"));
    }

    #[test]
    fn parse_get_request() {
        let head = b"GET /lodash/-/lodash-4.17.21.tgz HTTP/1.1\r\nHost: registry.npmjs.org\r\nUser-Agent: npm\r\nAccept: */*";
        let r = parse_request_head(head).unwrap();
        assert_eq!(r.method, "GET");
        assert_eq!(r.path, "/lodash/-/lodash-4.17.21.tgz");
        assert_eq!(r.host.as_deref(), Some("registry.npmjs.org"));
        assert!(r.keep_alive);
        assert!(!r.has_body);
    }

    #[test]
    fn parse_detects_body_and_close_and_http10() {
        let r = parse_request_head(b"POST /x HTTP/1.1\r\nHost: a\r\nContent-Length: 12").unwrap();
        assert!(r.has_body);
        let r = parse_request_head(b"GET /x HTTP/1.1\r\nHost: a\r\nConnection: close").unwrap();
        assert!(!r.keep_alive);
        let r = parse_request_head(b"GET /x HTTP/1.0\r\nHost: a").unwrap();
        assert!(!r.keep_alive); // 1.0 defaults to close
        let r = parse_request_head(b"GET /x HTTP/1.1\r\nHost: a\r\nTransfer-Encoding: chunked").unwrap();
        assert!(r.has_body);
        assert!(parse_request_head(b"garbage line").is_none());
    }

    #[test]
    fn index_entry_freshness() {
        let imm = IndexEntry {
            digest: "d".into(),
            content_type: None,
            content_encoding: None,
            immutable: true,
            fetched_at: 0,
        };
        assert!(imm.fresh(), "immutable never expires");
        let stale = IndexEntry {
            immutable: false,
            fetched_at: now_unix().saturating_sub(INDEX_TTL.as_secs() + 10),
            ..imm.clone()
        };
        assert!(!stale.fresh());
        let recent = IndexEntry {
            immutable: false,
            fetched_at: now_unix(),
            ..imm
        };
        assert!(recent.fresh());
    }

    #[tokio::test]
    async fn write_200_file_response_is_framed() {
        let dir = std::env::temp_dir().join(format!("jkb-mirror-resp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let blob = dir.join("blob");
        tokio::fs::write(&blob, b"PACKAGEBYTES").await.unwrap();
        let resp = MirrorResponse {
            status: 200,
            content_type: Some("application/octet-stream".into()),
            content_encoding: None,
            extra: vec![],
            body: ServeBody::File {
                path: blob,
                len: 12,
            },
        };
        let mut out = Vec::new();
        write_response(&mut out, resp, false, true).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Length: 12\r\n"));
        assert!(text.contains("Content-Type: application/octet-stream\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.ends_with("\r\n\r\nPACKAGEBYTES"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_head_only_suppresses_body() {
        let resp = MirrorResponse {
            status: 200,
            content_type: None,
            content_encoding: None,
            extra: vec![],
            body: ServeBody::Bytes(b"hello".to_vec()),
        };
        let mut out = Vec::new();
        write_response(&mut out, resp, true, false).await.unwrap();
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\n"), "HEAD must omit the body");
    }

    #[tokio::test]
    async fn read_head_terminates_on_crlfcrlf() {
        let data = b"GET / HTTP/1.1\r\nHost: a\r\n\r\nLEFTOVERBODY";
        let mut cur = std::io::Cursor::new(data.to_vec());
        let head = read_head(&mut cur).await.unwrap().unwrap();
        assert_eq!(head, b"GET / HTTP/1.1\r\nHost: a");
    }

    // THE dedup proof. Drives a real MITM'd fetch of an immutable npm tarball twice:
    // the first MISSes (one real upstream fetch, cert-validated vs public webpki roots),
    // the second HITs the shared store (no upstream) and serves byte-identical content
    // — i.e. a second tenant fetching the same dep reuses the first's download. Also
    // proves the runtime-issued leaf chains to the persisted CA over a real handshake.
    #[tokio::test]
    #[ignore = "needs outbound internet to registry.npmjs.org"]
    async fn mirror_dedups_real_registry_fetch() {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("jkb-mirror-dedup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca_dir = dir.join("build-ca");
        let ca = crate::build_ca::BuildCa::load_or_generate(&ca_dir).unwrap();
        let ca_pem = std::fs::read(ca_dir.join("ca.crt")).unwrap();
        let signer = Arc::new(crate::build_ca::CertSigner::new(ca));
        let mirror = MirrorTls::new(&dir, signer).unwrap();

        let host = "registry.npmjs.org";
        let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host, 443))
            .await
            .unwrap()
            .collect();
        let addr = crate::egress::pick_safe_addr(addrs).expect("a public npm addr");

        // Client trusts ONLY the mirror CA — so a successful fetch proves the leaf chains.
        let mut roots = rustls::RootCertStore::empty();
        for c in rustls_pemfile::certs(&mut &ca_pem[..]) {
            roots.add(c.unwrap()).unwrap();
        }
        let client_cfg = Arc::new(
            rustls::ClientConfig::builder()
                .with_root_certificates(roots)
                .with_no_client_auth(),
        );

        async fn fetch(
            mirror: &Arc<MirrorTls>,
            client_cfg: &Arc<rustls::ClientConfig>,
            host: &str,
            addr: SocketAddr,
            path: &str,
        ) -> Vec<u8> {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = listener.local_addr().unwrap();
            let m = mirror.clone();
            let h = host.to_string();
            let server = tokio::spawn(async move {
                let (sock, _) = listener.accept().await.unwrap();
                m.handle_mitm(sock, h, addr).await;
            });
            let tcp = TcpStream::connect(local).await.unwrap();
            let connector = tokio_rustls::TlsConnector::from(client_cfg.clone());
            let sni = rustls::pki_types::ServerName::try_from(host.to_string()).unwrap();
            let mut tls = connector.connect(sni, tcp).await.unwrap();
            let req = format!(
                "GET {path} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: test\r\nConnection: close\r\n\r\n"
            );
            tls.write_all(req.as_bytes()).await.unwrap();
            let mut buf = Vec::new();
            tls.read_to_end(&mut buf).await.unwrap();
            let _ = server.await;
            buf
        }

        let path = "/lodash/-/lodash-4.17.21.tgz"; // immutable npm tarball
        let (h0, f0) = mirror.stats();
        let r1 = fetch(&mirror, &client_cfg, host, addr, path).await;
        let (_h1, f1) = mirror.stats();
        let r2 = fetch(&mirror, &client_cfg, host, addr, path).await;
        let (h2, f2) = mirror.stats();

        assert!(
            r1.starts_with(b"HTTP/1.1 200 OK"),
            "first response not 200: {:?}",
            String::from_utf8_lossy(&r1[..r1.len().min(64)])
        );
        assert_eq!(r1, r2, "served bytes must be identical across tenants");
        assert_eq!(f1, f0 + 1, "first request must MISS -> exactly one upstream fetch");
        assert_eq!(f2, f1, "second request must HIT -> NO second upstream fetch (dedup)");
        assert_eq!(h2, h0 + 1, "second request must be served from the shared store");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
