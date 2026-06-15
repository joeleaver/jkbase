//! The tenant-facing S3 object-store HTTP service (host `storage.{domain}`).
//!
//! This is the multi-tenant front for the `jkbase-objectstore` engine. The engine
//! is a single-store library; here we add what makes it a platform product:
//!
//! - **SigV4 → project**: every request is authenticated with the control plane's
//!   access-key store. The key resolves to exactly one project, and the request is
//!   served from THAT project's object-store root (`{data_dir}/objectstore/{id}`) —
//!   filesystem-level tenant isolation, not a shared namespace + ACL.
//! - **Host binding**: SigV4 signs the `Host` header, but the edge proxy rewrites
//!   Host to the local backend address when forwarding. We therefore verify against
//!   a CONFIGURED public host (`storage.{domain}`), never the received one.
//! - **Quota**: object writes are gated against the project's storage cap with an
//!   authoritative base (re-walked on a TTL) plus an in-flight reservation that
//!   fails CLOSED — it over-counts rather than under, so the cap can't be raced.
//!
//! Per the no-S3-for-control-plane rule this never touches the control app's state;
//! it runs as its own local listener that the proxy forwards `storage.{domain}` to.

use axum::{
    Router,
    extract::{Request, State},
    http::{StatusCode, header},
    response::{IntoResponse, Response},
};
use jkbase_control::store::{DEFAULT_QUOTA, QuotaLimits, Store};
use jkbase_objectstore::{ObjectStore, sigv4};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tower::ServiceExt; // oneshot
use tracing::warn;

/// How often a project's authoritative on-disk footprint is re-walked. Between
/// refreshes, write reservations accumulate so the cap holds within the window;
/// short enough that deleted space frees quickly, long enough to keep the dir-walk
/// off the per-request hot path (and out of reach as an O(n²) amplifier).
const QUOTA_TTL: Duration = Duration::from_secs(10);

/// Bound the per-project entry cache so a churn of distinct project ids can't grow
/// it without limit. Entries are cheap to reopen (a stateless `ObjectStore` + fresh
/// usage counters) and the per-request owner re-check makes a stale one safe, so
/// arbitrary eviction when over the cap is fine.
const PROJECT_CACHE_CAP: usize = 4096;

/// Cap on concurrent in-flight (un-completed) multipart uploads per project — a
/// floor against `.uploads/{id}` staging-dir / inode amplification (staging already
/// counts toward the tenant's own byte quota, so this is defense-in-depth).
const MAX_INFLIGHT_UPLOADS: u64 = 1000;

/// Mutable per-project usage accounting, guarded by its OWN lock so one project's
/// (potentially large) dir-walk never blocks another project's requests. Both bytes
/// AND object count are gated; each carries an in-flight reservation that fails
/// CLOSED (over-counts) until the next authoritative TTL re-walk reconciles it.
struct Usage {
    base_bytes: u64,
    base_objects: u64,
    base_buckets: u64,
    sampled_at: Instant,
    reserved_bytes: u64,
    reserved_objects: u64,
    reserved_buckets: u64,
}

struct ProjectEntry {
    store: Arc<ObjectStore>,
    usage: Mutex<Usage>,
}

pub struct ObjectStoreService {
    data_dir: PathBuf,
    control: Store,
    public_host: String,
    projects: Mutex<HashMap<String, Arc<ProjectEntry>>>,
}

impl ObjectStoreService {
    pub fn new(data_dir: PathBuf, control: Store, public_host: String) -> Self {
        Self {
            data_dir,
            control,
            public_host,
            projects: Mutex::new(HashMap::new()),
        }
    }

    /// The axum app: a single fallback that authenticates, resolves the project,
    /// gates writes, and dispatches into the per-project engine router.
    pub fn into_router(self: Arc<Self>) -> Router {
        Router::new().fallback(dispatch).with_state(self)
    }

    /// Get-or-open the per-project entry. Opening creates `{data_dir}/objectstore/{id}`
    /// lazily (mirrors how data disks / content images are made on first use).
    fn project_entry(&self, project_id: &str) -> std::io::Result<Arc<ProjectEntry>> {
        // Defense-in-depth: project_id becomes a path component for the store root.
        // The control plane only ever mints keys for validated `[a-z0-9-]` slugs, but
        // refuse to join anything else (esp. empty → the shared `objectstore/` parent)
        // so a malformed id that ever lands in ACCESS_KEYS fails closed here too.
        if !is_valid_project_id(project_id) {
            return Err(std::io::Error::other(format!(
                "invalid project id {project_id:?}"
            )));
        }
        let mut map = self.projects.lock().unwrap();
        if let Some(e) = map.get(project_id) {
            return Ok(e.clone());
        }
        let root = self.data_dir.join("objectstore").join(project_id);
        let store = ObjectStore::open(&root)
            .map_err(|e| std::io::Error::other(format!("open object store: {e}")))?;
        let entry = Arc::new(ProjectEntry {
            store: Arc::new(store),
            usage: Mutex::new(Usage {
                base_bytes: 0,
                base_objects: 0,
                base_buckets: 0,
                // Force a fresh walk on the first write (sampled "in the past").
                sampled_at: Instant::now()
                    .checked_sub(QUOTA_TTL)
                    .unwrap_or_else(Instant::now),
                reserved_bytes: 0,
                reserved_objects: 0,
                reserved_buckets: 0,
            }),
        });
        // Keep the cache bounded: evict an arbitrary entry once at capacity (cheap to
        // reopen). Never evicts the one we're about to insert.
        if map.len() >= PROJECT_CACHE_CAP && !map.contains_key(project_id)
            && let Some(victim) = map.keys().next().cloned()
        {
            map.remove(&victim);
        }
        map.insert(project_id.to_string(), entry.clone());
        Ok(entry)
    }

    /// Drop a project's cached entry (e.g. after the project is deleted/recreated).
    /// Self-healing today via the per-request owner re-check + stateless store, so
    /// this is an opportunistic eviction the cache bound also covers.
    #[allow(dead_code)]
    pub fn invalidate(&self, project_id: &str) {
        self.projects.lock().unwrap().remove(project_id);
    }

    /// Re-walk the project's authoritative on-disk footprint when the cached sample is
    /// stale, OFF the per-project lock (`spawn_blocking` for bytes + an async count
    /// walk), so one project's walk never blocks its own — or any other's — requests.
    ///
    /// Fail-CLOSED: if the count walk errors (a real IO fault on the store root),
    /// return an error response rather than adopt a zeroed base that would let writes
    /// slip past the object/bucket caps for a TTL window.
    async fn refresh_if_stale(
        &self,
        entry: &Arc<ProjectEntry>,
        project_id: &str,
    ) -> Result<(), Response> {
        let stale = { entry.usage.lock().unwrap().sampled_at.elapsed() > QUOTA_TTL };
        if !stale {
            return Ok(());
        }
        let dd = self.data_dir.clone();
        let pid = project_id.to_string();
        let bytes = tokio::task::spawn_blocking(move || {
            jkbase_common::storage::project_storage_bytes(&dd, &pid)
        })
        .await
        .unwrap_or(0);
        let (buckets, objects) = match entry.store.usage_counts().await {
            Ok(c) => c,
            Err(e) => {
                warn!(project = %project_id, error = %e, "object store usage walk failed");
                return Err(s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "quota check temporarily unavailable",
                ));
            }
        };
        let mut u = entry.usage.lock().unwrap();
        // Re-check under the lock: don't clobber a fresher concurrent refresh.
        if u.sampled_at.elapsed() > QUOTA_TTL {
            u.base_bytes = bytes;
            u.base_objects = objects;
            u.base_buckets = buckets;
            u.reserved_bytes = 0;
            u.reserved_objects = 0;
            u.reserved_buckets = 0;
            u.sampled_at = Instant::now();
        }
        Ok(())
    }

    /// Reserve `len` bytes (and, when `adds_object`, one object) against the storage +
    /// object-count caps under the per-project lock. The reservation is added BEFORE
    /// the write and held until the next TTL re-walk, so concurrent writes within a
    /// window can't overshoot (fail-closed: it over-counts rather than under).
    async fn refresh_and_reserve(
        &self,
        entry: &Arc<ProjectEntry>,
        project_id: &str,
        len: u64,
        adds_object: bool,
        quota: &QuotaLimits,
    ) -> Option<Response> {
        if let Err(resp) = self.refresh_if_stale(entry, project_id).await {
            return Some(resp);
        }
        let mut u = entry.usage.lock().unwrap();
        let projected_bytes = u.base_bytes.saturating_add(u.reserved_bytes).saturating_add(len);
        if projected_bytes > quota.storage_bytes_max {
            return Some(s3_error(
                StatusCode::INSUFFICIENT_STORAGE,
                "QuotaExceeded",
                &format!(
                    "storage quota exceeded: would use {projected_bytes} bytes, cap is {}",
                    quota.storage_bytes_max
                ),
            ));
        }
        if adds_object {
            let projected_objs = u.base_objects.saturating_add(u.reserved_objects).saturating_add(1);
            if projected_objs > quota.max_objects {
                return Some(s3_error(
                    StatusCode::INSUFFICIENT_STORAGE,
                    "TooManyObjects",
                    &format!(
                        "object-count quota exceeded: would hold {projected_objs} objects, cap is {}",
                        quota.max_objects
                    ),
                ));
            }
            u.reserved_objects = u.reserved_objects.saturating_add(1);
        }
        u.reserved_bytes = u.reserved_bytes.saturating_add(len);
        None
    }

    /// Reserve one bucket against `max_buckets` under the per-project lock — closes the
    /// check-then-create race a raw `list_buckets` count would leave open (two
    /// concurrent creates both seeing room) and is fail-closed on the count walk.
    async fn reserve_bucket(
        &self,
        entry: &Arc<ProjectEntry>,
        project_id: &str,
        quota: &QuotaLimits,
    ) -> Option<Response> {
        if let Err(resp) = self.refresh_if_stale(entry, project_id).await {
            return Some(resp);
        }
        let mut u = entry.usage.lock().unwrap();
        let projected = u.base_buckets.saturating_add(u.reserved_buckets).saturating_add(1);
        if projected > quota.max_buckets {
            return Some(s3_error(
                StatusCode::CONFLICT,
                "TooManyBuckets",
                &format!("bucket quota exceeded: cap is {}", quota.max_buckets),
            ));
        }
        u.reserved_buckets = u.reserved_buckets.saturating_add(1);
        None
    }

    /// Release a byte/object reservation when the write didn't land (non-2xx),
    /// crediting it back instead of waiting out the TTL.
    fn release_reservation(&self, entry: &ProjectEntry, len: u64, had_object: bool) {
        let mut u = entry.usage.lock().unwrap();
        u.reserved_bytes = u.reserved_bytes.saturating_sub(len);
        if had_object {
            u.reserved_objects = u.reserved_objects.saturating_sub(1);
        }
    }

    /// Release a bucket reservation when the create didn't land (non-2xx).
    fn release_bucket_reservation(&self, entry: &ProjectEntry) {
        let mut u = entry.usage.lock().unwrap();
        u.reserved_buckets = u.reserved_buckets.saturating_sub(1);
    }

    /// Force the project's next quota check to re-walk (e.g. after a delete frees
    /// space/objects) so reclaimed capacity is credited promptly, not in ≤TTL.
    fn invalidate_usage_sample(&self, entry: &ProjectEntry) {
        let mut u = entry.usage.lock().unwrap();
        u.sampled_at = Instant::now()
            .checked_sub(QUOTA_TTL)
            .unwrap_or_else(Instant::now);
    }

    /// Sweep abandoned multipart staging across every registered project. Returns the
    /// total number of stale `.uploads/{id}` dirs removed. Driven on boot + on a timer.
    pub async fn sweep_all_stale_uploads(&self, max_age: Duration) -> usize {
        let projects = match self.control.list_projects() {
            Ok(p) => p,
            Err(_) => return 0,
        };
        let mut total = 0usize;
        for p in projects {
            if !is_valid_project_id(&p.id) {
                continue;
            }
            let root = self.data_dir.join("objectstore").join(&p.id);
            if !tokio::fs::try_exists(&root).await.unwrap_or(false) {
                continue;
            }
            if let Ok(store) = ObjectStore::open(&root)
                && let Ok(n) = store.sweep_stale_uploads(max_age).await
            {
                total += n;
            }
        }
        total
    }

    async fn handle(&self, req: Request) -> Response {
        // --- 1. Authenticate (SigV4) against the CONFIGURED public host. The edge
        // proxy rewrites Host to the local backend, so we verify the signed host
        // ourselves; accept the bare public host AND its :443/:80 variants for SDKs/
        // CLIs that sign the port (fail-closed against any other host). ---
        let method = req.method().as_str().to_string();
        let path = pct_decode(req.uri().path());
        let query = parse_query(req.uri().query().unwrap_or(""));
        let now = now_secs();
        let is_presigned = query.iter().any(|(k, _)| k == "X-Amz-Signature");
        let header_auth = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|s| s.to_string());
        let headers = lower_headers(&req);

        let mut auth = Err("anonymous requests are not allowed".to_string());
        for host in self.host_candidates() {
            let lookup = |akid: &str| {
                self.control.lookup_access_key(akid).ok().flatten().map(|k| k.secret_key)
            };
            auth = if is_presigned {
                sigv4::verify_presigned(&method, &host, &path, &query, lookup, now)
            } else if let Some(a) = header_auth.as_deref() {
                sigv4::verify_header(&method, &host, &path, &query, &headers, a, lookup, now)
            } else {
                break; // anonymous: no point trying other hosts
            };
            if auth.is_ok() {
                break;
            }
        }
        let access_key_id = match auth {
            Ok(k) => k,
            Err(e) => return s3_access_denied(&e),
        };

        // --- 2. Resolve the owning project from the key (authoritative tenancy). ---
        let key = match self.control.lookup_access_key(&access_key_id) {
            Ok(Some(k)) => k,
            _ => return s3_access_denied("unknown access key"),
        };
        let project_id = key.project_id.clone();

        // Re-bind to the project's CURRENT owner (mirrors the git-push token guard): a
        // key orphaned by a crash-interrupted teardown must not be honored once a
        // DIFFERENT tenant recreates the same-slug project. Fails closed if the project
        // is gone or the owner changed.
        match self.control.get_project(&project_id) {
            Ok(Some(p)) if p.tenant_id.as_deref() == Some(key.tenant_id.as_str()) => {}
            _ => return s3_access_denied("access key not valid for the current project owner"),
        }

        let entry = match self.project_entry(&project_id) {
            Ok(e) => e,
            Err(e) => {
                warn!(project = %project_id, error = %e, "object store open failed");
                return s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "object store unavailable",
                );
            }
        };

        let quota = self.control.get_quota(&project_id).unwrap_or(DEFAULT_QUOTA);

        // --- 3a. Cap bucket COUNT at create (PUT /{bucket}) via a lock-held reservation. ---
        let mut bucket_reserved = false;
        if is_bucket_create(&method, &path) {
            if let Some(resp) = self.reserve_bucket(&entry, &project_id, &quota).await {
                return resp;
            }
            bucket_reserved = true;
        }

        // --- 3b. Cap concurrent in-flight multipart uploads (POST ?uploads). ---
        if is_create_multipart(&method, &query) {
            // Fail closed: a count-walk error counts as "at cap", not "empty".
            let inflight = entry
                .store
                .count_inflight_uploads(MAX_INFLIGHT_UPLOADS)
                .await
                .unwrap_or(MAX_INFLIGHT_UPLOADS);
            if inflight >= MAX_INFLIGHT_UPLOADS {
                return s3_error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "SlowDown",
                    "too many in-flight multipart uploads; complete or abort some first",
                );
            }
        }

        // --- 3c. Gate byte-adding writes against the storage + object-count caps. A
        // plain PUT adds one object; an UploadPart adds bytes only; CompleteMultipart
        // adds one object (its bytes were counted as parts). ---
        let mut reservation: Option<(u64, bool)> = None;
        if is_object_write(&method, &path) {
            let adds_object = !is_upload_part(&query);
            match write_len(&req) {
                Some(len) => {
                    if let Some(resp) = self
                        .refresh_and_reserve(&entry, &project_id, len, adds_object, &quota)
                        .await
                    {
                        return resp;
                    }
                    reservation = Some((len, adds_object));
                }
                None => {
                    return s3_error(
                        StatusCode::LENGTH_REQUIRED,
                        "MissingContentLength",
                        "object writes require a Content-Length",
                    );
                }
            }
        } else if is_complete_multipart(&method, &query) {
            if let Some(resp) = self
                .refresh_and_reserve(&entry, &project_id, 0, true, &quota)
                .await
            {
                return resp;
            }
            reservation = Some((0, true));
        }

        // --- 4. Serve from the project's own store. Route on the SAME canonical path
        // the signature covered (re-encode the verified, pct-decoded path) so a crafted
        // `%2F` can't sign one key yet route another. Cap the body to the reservation:
        // the declared length is NOT a signed header and the engine streams to EOF, so
        // without this a client could reserve 1 byte and stream unbounded onto the
        // shared disk. Exceeding the cap errors the body mid-stream → the engine aborts.
        let req = set_canonical_path(req, &path);
        let req = match reservation {
            Some((len, _)) if len > 0 => limit_body(req, len),
            _ => req,
        };
        let app = jkbase_objectstore::router(entry.store.clone());
        let resp = match app.oneshot(req).await {
            Ok(resp) => resp,
            Err(e) => match e {}, // Router error is Infallible
        };

        // --- 5. Reconcile the reservation against the outcome. ---
        if let Some((len, had_object)) = reservation
            && !resp.status().is_success()
        {
            // The write didn't land — credit the reservation back immediately.
            self.release_reservation(&entry, len, had_object);
        }
        if bucket_reserved && !resp.status().is_success() {
            self.release_bucket_reservation(&entry);
        }
        if method == "DELETE" && path_has_key(&path) && resp.status().is_success() {
            // A delete (or AbortMultipartUpload) freed space/objects: re-walk on the
            // next request rather than wait out the TTL.
            self.invalidate_usage_sample(&entry);
        }
        resp
    }

    /// Host values to try when verifying the signed `host`: the configured public
    /// host plus the `:443`/`:80` variants some SDKs/CLIs sign.
    fn host_candidates(&self) -> [String; 3] {
        [
            self.public_host.clone(),
            format!("{}:443", self.public_host),
            format!("{}:80", self.public_host),
        ]
    }
}

async fn dispatch(State(svc): State<Arc<ObjectStoreService>>, req: Request) -> Response {
    svc.handle(req).await
}

/// Replace the request body with one hard-capped at `max` bytes. Reading past `max`
/// yields an error, which the engine surfaces as a failed (aborted) write — making
/// the quota reservation authoritative regardless of the (unsigned) declared length.
fn limit_body(req: Request, max: u64) -> Request {
    let (parts, body) = req.into_parts();
    let limited = http_body_util::Limited::new(body, max as usize);
    Request::from_parts(parts, axum::body::Body::new(limited))
}

/// A byte-adding object write = PUT on an object path (`/{bucket}/{key}`): a plain
/// object put or a multipart UploadPart. Bucket creates (`PUT /{bucket}`) add no
/// object bytes; GET/HEAD/DELETE/POST are not gated here (parts are gated at upload,
/// and CompleteMultipart only concatenates already-counted parts).
fn is_object_write(method: &str, path: &str) -> bool {
    method == "PUT" && path_has_key(path)
}

/// True when the path has a non-empty key segment after the bucket.
fn path_has_key(path: &str) -> bool {
    let mut it = path.trim_start_matches('/').splitn(2, '/');
    let _bucket = it.next();
    it.next().is_some_and(|k| !k.is_empty())
}

/// A valid project id = the slug the control plane mints (`[a-z0-9-]`, 1..=63). Used
/// both as the store-root path component (must never be empty → the shared parent)
/// and to skip junk dirs in the multipart sweeper.
fn is_valid_project_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A bucket create = `PUT /{bucket}` with no key segment.
fn is_bucket_create(method: &str, path: &str) -> bool {
    method == "PUT" && !path_has_key(path) && path.trim_start_matches('/').split('/').next().is_some_and(|b| !b.is_empty())
}

/// InitiateMultipartUpload = `POST …?uploads`.
fn is_create_multipart(method: &str, query: &[(String, String)]) -> bool {
    method == "POST" && query.iter().any(|(k, _)| k == "uploads")
}

/// CompleteMultipartUpload = `POST …?uploadId=..` (without `?uploads`).
fn is_complete_multipart(method: &str, query: &[(String, String)]) -> bool {
    method == "POST"
        && query.iter().any(|(k, _)| k == "uploadId")
        && !query.iter().any(|(k, _)| k == "uploads")
}

/// UploadPart = a PUT carrying `?uploadId=..&partNumber=..` (bytes, but not a new
/// object — the object materializes at CompleteMultipartUpload).
fn is_upload_part(query: &[(String, String)]) -> bool {
    query.iter().any(|(k, _)| k == "uploadId") && query.iter().any(|(k, _)| k == "partNumber")
}

/// RFC-3986 path encoding matching the SigV4 canonical form (`uri_encode(path,
/// encode_slash=false)`): unreserved chars verbatim, `/` preserved, everything else
/// percent-encoded. Re-encoding the verified (pct-decoded) path with this yields a
/// URI axum decodes back to exactly that path — so routing matches what was signed.
fn uri_encode_path(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => out.push(b as char),
            b'/' => out.push('/'),
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Rewrite the request's path to the canonical re-encoding of `decoded_path`
/// (preserving the raw query), so the engine routes the SAME bucket/key the SigV4
/// signature was verified over. A no-op for already-canonical requests.
fn set_canonical_path(req: Request, decoded_path: &str) -> Request {
    let (mut parts, body) = req.into_parts();
    let canon = uri_encode_path(decoded_path);
    let pq = match parts.uri.query() {
        Some(q) => format!("{canon}?{q}"),
        None => canon,
    };
    if let Ok(uri) = pq.parse::<axum::http::Uri>() {
        parts.uri = uri;
    }
    Request::from_parts(parts, body)
}

/// Declared body length for a write: `Content-Length`, or the AWS streaming header
/// `x-amz-decoded-content-length`. `None` => unknown (caller rejects with 411), so a
/// client can't dodge the quota gate by omitting the length.
fn write_len(req: &Request) -> Option<u64> {
    let h = req.headers();
    h.get(header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            h.get("x-amz-decoded-content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.parse::<u64>().ok())
        })
}

fn lower_headers(req: &Request) -> HashMap<String, String> {
    req.headers()
        .iter()
        .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_lowercase(), s.to_string())))
        .collect()
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Parse a query string into decoded (key, value) pairs (matches the engine's own
/// canonicalisation input so SigV4 verifies identically).
fn parse_query(qs: &str) -> Vec<(String, String)> {
    if qs.is_empty() {
        return Vec::new();
    }
    qs.split('&')
        .map(|kv| match kv.split_once('=') {
            Some((k, v)) => (pct_decode(k), pct_decode(v)),
            None => (pct_decode(kv), String::new()),
        })
        .collect()
}

fn pct_decode(s: &str) -> String {
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(b.len());
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' && i + 2 < b.len() {
            match u8::from_str_radix(&s[i + 1..i + 3], 16) {
                Ok(h) => {
                    out.push(h);
                    i += 3;
                }
                Err(_) => {
                    out.push(b'%');
                    i += 1;
                }
            }
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn s3_error(status: StatusCode, code: &str, msg: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{}</Message></Error>",
        xml_escape(msg)
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn s3_access_denied(msg: &str) -> Response {
    s3_error(StatusCode::FORBIDDEN, "AccessDenied", msg)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::{Body, to_bytes};
    use axum::http::Request as HttpRequest;

    /// On-box e2e over real TCP/HTTP via reqwest. Proves SigV4 verifies on the wire
    /// AND that host-binding uses the CONFIGURED public host (the request's actual Host
    /// is `127.0.0.1:port`, but the signature is for `storage.jkbase.app`) — the exact
    /// property that makes the service correct behind the Host-rewriting proxy.
    /// `#[ignore]` because it binds a port; run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn e2e_over_real_http() {
        let dir = tmp("e2e");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let k = store.create_access_key("proj", "tenant-x", "ci").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.jkbase.app".to_string(),
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, svc.into_router()).await.unwrap();
        });
        let base = format!("http://{addr}");
        let client = reqwest::Client::new();

        // Sign for the PUBLIC host, not the connection address.
        let send = |method: &'static str, path: String, body: &'static str| {
            let client = client.clone();
            let base = base.clone();
            let akid = k.access_key_id.clone();
            let secret = k.secret_key.clone();
            async move {
                let (auth, amzd) = sigv4::sign_header(
                    method, "storage.jkbase.app", &path, &[], "UNSIGNED-PAYLOAD",
                    &akid, &secret, "us-east-1", now_secs(),
                );
                let rb = client
                    .request(reqwest::Method::from_bytes(method.as_bytes()).unwrap(), format!("{base}{path}"))
                    .header("authorization", auth)
                    .header("x-amz-date", amzd)
                    .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                    .body(body);
                let resp = rb.send().await.unwrap();
                (resp.status().as_u16(), resp.text().await.unwrap())
            }
        };

        // Create bucket -> PUT object -> GET (verify) -> LIST -> DELETE -> GET 404.
        assert_eq!(send("PUT", "/photos".into(), "").await.0, 200);
        assert_eq!(send("PUT", "/photos/cat.txt".into(), "meow").await.0, 200);
        let (gst, gbody) = send("GET", "/photos/cat.txt".into(), "").await;
        assert_eq!(gst, 200);
        assert_eq!(gbody, "meow");
        let (lst, lbody) = send("GET", "/photos".into(), "").await;
        assert_eq!(lst, 200);
        assert!(lbody.contains("<Key>cat.txt</Key>"), "list: {lbody}");
        assert_eq!(send("DELETE", "/photos/cat.txt".into(), "").await.0, 204);
        assert_eq!(send("GET", "/photos/cat.txt".into(), "").await.0, 404);

        // An unsigned request is refused over the wire too.
        let anon = client.get(format!("{base}/photos/cat.txt")).send().await.unwrap();
        assert_eq!(anon.status().as_u16(), 403);

        let _ = std::fs::remove_dir_all(&dir);
    }

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-objsvc-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn store_at(dir: &PathBuf) -> Store {
        std::fs::create_dir_all(dir).unwrap();
        Store::open(&dir.join("ctl.redb")).unwrap()
    }

    /// Insert a project owned by `tenant` (the storage service re-checks key ↔ current
    /// project owner on every request, so tests must register the project).
    fn mk_project(store: &Store, id: &str, tenant: &str) {
        use jkbase_control::store::{Project, ProjectState};
        store
            .create_project(&Project {
                id: id.to_string(),
                name: id.to_string(),
                tenant_id: Some(tenant.to_string()),
                current_version: None,
                state: ProjectState::Stopped,
                vm_ip: None,
                domains: Vec::new(),
            })
            .unwrap();
    }

    /// Build a SigV4 header-signed request for the service's public host.
    fn signed(method: &str, path: &str, akid: &str, secret: &str, body: &str) -> Request {
        let (auth, amzd) = sigv4::sign_header(
            method, "storage.test", path, &[], "UNSIGNED-PAYLOAD", akid, secret, "us-east-1", now_secs(),
        );
        HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("content-length", body.len().to_string())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    async fn status_body(resp: Response) -> (StatusCode, String) {
        let status = resp.status();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn signed_put_get_round_trip_and_tenant_isolation() {
        let dir = tmp("rt");
        let store = store_at(&dir);
        mk_project(&store, "proj-a", "tenant-a");
        mk_project(&store, "proj-b", "tenant-b");
        let a = store.create_access_key("proj-a", "tenant-a", "t").unwrap();
        let b = store.create_access_key("proj-b", "tenant-b", "t").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();

        // Anonymous -> 403.
        let r = app
            .clone()
            .oneshot(HttpRequest::get("/bkt/k").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // tenant-a: create bucket + put + get.
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, "")).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt/hello.txt", &a.access_key_id, &a.secret_key, "hi there")).await.unwrap().status(),
            StatusCode::OK
        );
        let (st, body) = status_body(
            app.clone().oneshot(signed("GET", "/bkt/hello.txt", &a.access_key_id, &a.secret_key, "")).await.unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, "hi there");

        // tenant-b signs validly but has its OWN store root -> /bkt doesn't exist for it.
        let r = app
            .clone()
            .oneshot(signed("GET", "/bkt/hello.txt", &b.access_key_id, &b.secret_key, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND); // NoSuchBucket in b's namespace

        // Wrong secret -> 403.
        let r = app
            .clone()
            .oneshot(signed("GET", "/bkt/hello.txt", &a.access_key_id, "WRONG", ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn orphaned_key_rejected_after_owner_change() {
        // A key minted by tenant A, then the project is torn down WITHOUT purging the
        // key (crash) and recreated by tenant B (same slug). A's orphaned key must NOT
        // authenticate against B's store — the owner re-check fails closed.
        let dir = tmp("rebind");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-a");
        let k = store.create_access_key("proj", "tenant-a", "").unwrap();
        // Simulate same-slug recreate by a different tenant (key left orphaned).
        store.delete_project("proj").unwrap();
        mk_project(&store, "proj", "tenant-b");
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        let r = app
            .clone()
            .oneshot(signed("GET", "/bkt/x", &k.access_key_id, &k.secret_key, ""))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN, "orphaned key must not work after owner change");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn empty_project_id_key_cannot_reach_the_shared_root() {
        // Regression for the empty-slug BLOCKER: a key whose project_id is "" must NOT
        // resolve its store root to the shared `objectstore/` parent (which would list
        // every other project as a "bucket"). project_entry must fail closed.
        let dir = tmp("emptyproj");
        let store = store_at(&dir);
        let data = dir.join("data");
        // A real victim project with a bucket sitting under the shared objectstore root.
        std::fs::create_dir_all(data.join("objectstore").join("victim-proj").join("secret-bkt")).unwrap();
        let bad = store.create_access_key("", "attacker", "evil").unwrap(); // empty project id
        let svc = Arc::new(ObjectStoreService::new(data, store, "storage.test".to_string()));
        let app = svc.into_router();

        // GET / would, without the guard, list the shared root (every project id).
        let (st, body) = status_body(
            app.clone().oneshot(signed("GET", "/", &bad.access_key_id, &bad.secret_key, "")).await.unwrap(),
        )
        .await;
        assert_ne!(st, StatusCode::OK, "empty-project key must not succeed");
        assert!(!body.contains("victim-proj"), "must not leak other projects' ids");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn body_exceeding_declared_length_is_capped_and_rejected() {
        // A client declares a tiny Content-Length (reserves tiny) but streams more —
        // the body must be capped at the reservation so it can't fill the shared disk.
        let dir = tmp("cap");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, "")).await.unwrap().status(),
            StatusCode::OK
        );
        // Declare length 2 but send 100 bytes.
        let (auth, amzd) = sigv4::sign_header(
            "PUT", "storage.test", "/bkt/k", &[], "UNSIGNED-PAYLOAD", &a.access_key_id, &a.secret_key, "us-east-1", now_secs(),
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/bkt/k")
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("content-length", "2")
            .body(Body::from("x".repeat(100)))
            .unwrap();
        let st = app.clone().oneshot(req).await.unwrap().status();
        assert_ne!(st, StatusCode::OK, "over-length write must not succeed");
        // And the object must not be readable as the full 100 bytes.
        let (gst, gbody) = status_body(
            app.clone().oneshot(signed("GET", "/bkt/k", &a.access_key_id, &a.secret_key, "")).await.unwrap(),
        )
        .await;
        assert!(gst != StatusCode::OK || gbody.len() <= 2, "must not store beyond the reservation");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_without_content_length_is_rejected() {
        let dir = tmp("nolen");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        // Sign a PUT but strip content-length -> 411 (can't dodge the quota gate).
        let (auth, amzd) = sigv4::sign_header(
            "PUT", "storage.test", "/bkt/k", &[], "UNSIGNED-PAYLOAD", &a.access_key_id, &a.secret_key, "us-east-1", now_secs(),
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/bkt/k")
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(Body::from("data"))
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::LENGTH_REQUIRED);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bucket_count_quota_enforced() {
        let dir = tmp("bktcap");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let mut q = DEFAULT_QUOTA;
        q.max_buckets = 1;
        store.set_quota("proj", &q).unwrap();
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/aaa", &a.access_key_id, &a.secret_key, "")).await.unwrap().status(),
            StatusCode::OK
        );
        let (st, body) = status_body(
            app.clone().oneshot(signed("PUT", "/bbb", &a.access_key_id, &a.secret_key, "")).await.unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert!(body.contains("TooManyBuckets"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn object_count_quota_enforced() {
        let dir = tmp("objcap");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let mut q = DEFAULT_QUOTA;
        q.max_objects = 1;
        store.set_quota("proj", &q).unwrap();
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, "")).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt/o1", &a.access_key_id, &a.secret_key, "x")).await.unwrap().status(),
            StatusCode::OK
        );
        // A second object exceeds the count cap within the TTL window -> 507.
        let (st, body) = status_body(
            app.clone().oneshot(signed("PUT", "/bkt/o2", &a.access_key_id, &a.secret_key, "y")).await.unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE);
        assert!(body.contains("TooManyObjects"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn signed_host_port_variant_is_accepted() {
        // A client signing `storage.test:443` (port included) must still verify against
        // the bare configured host `storage.test`.
        let dir = tmp("hostport");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(dir.join("data"), store, "storage.test".to_string()));
        let app = svc.into_router();
        let (auth, amzd) = sigv4::sign_header(
            "PUT", "storage.test:443", "/bkt", &[], "UNSIGNED-PAYLOAD",
            &a.access_key_id, &a.secret_key, "us-east-1", now_secs(),
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/bkt")
            .header("host", "storage.test:443")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("content-length", "0")
            .body(Body::empty())
            .unwrap();
        assert_eq!(app.oneshot(req).await.unwrap().status(), StatusCode::OK);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn canonical_path_keeps_slashes_and_encodes_the_rest() {
        // Route-on-same-form: re-encode the verified path so the engine routes exactly
        // what SigV4 signed. No-op for normal keys; percent-encodes the rest.
        assert_eq!(uri_encode_path("/bkt/a/b/c.txt"), "/bkt/a/b/c.txt");
        assert_eq!(uri_encode_path("/bkt/hello world"), "/bkt/hello%20world");
        assert_eq!(uri_encode_path("/bkt/a+b%"), "/bkt/a%2Bb%25");
    }
}
