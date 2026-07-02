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
    Json, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use futures_util::TryStreamExt;
use jkbase_control::store::{DEFAULT_QUOTA, QuotaLimits, Store};
use jkbase_objectstore::{
    ObjectError, ObjectStore, cors, cors_config_to_xml, parse_cors_config_xml, sigv4,
};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio_util::io::{ReaderStream, StreamReader};
use tower::ServiceExt; // oneshot
use tower_http::cors::CorsLayer;
use tracing::warn;

/// How often a project's authoritative on-disk footprint is re-walked. Between
/// refreshes, write reservations accumulate so the cap holds within the window;
/// short enough that deleted space frees quickly AND that the documented soft-cap
/// overshoot window (a tenant's own concurrent writes racing a re-walk) stays small,
/// long enough to keep the dir-walk off the per-request hot path (and out of reach
/// as an O(n²) amplifier). Lowered 10s→3s to tighten the overshoot window ~3×
/// (residual #1) — the full hard cap would need per-mutation ledger reconciliation.
const QUOTA_TTL: Duration = Duration::from_secs(3);

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
        // The Bearer-authenticated CONSOLE object API (`/_console/*`) lives on this same
        // service — the only component allowed to touch a tenant's store (the control
        // plane must not, per the no-S3-for-control-plane rule). It reuses this service's
        // per-project isolation + quota machinery; auth is the session Bearer token, not
        // SigV4, so no tenant secret ever reaches the browser. CORS is scoped to the
        // console sub-router only — the S3 fallback gets no CORS headers. The `_console`
        // path can't collide with a bucket (underscore is illegal in bucket names).
        let cors = self.console_cors();
        let console = Router::new()
            .route(
                "/_console/projects/{id}/buckets",
                get(console_list_buckets).post(console_create_bucket),
            )
            .route(
                "/_console/projects/{id}/buckets/{bucket}",
                delete(console_delete_bucket),
            )
            .route(
                "/_console/projects/{id}/buckets/{bucket}/objects",
                get(console_list_objects),
            )
            .route(
                "/_console/projects/{id}/buckets/{bucket}/object",
                get(console_get_object)
                    .put(console_put_object)
                    .delete(console_delete_object),
            )
            .layer(cors);
        Router::new()
            .merge(console)
            .fallback(dispatch)
            .with_state(self)
    }

    /// CORS for the Bearer console API: allow the platform's console origins (mirrors
    /// the control plane's allowlist) to call the `_console/*` object endpoints with
    /// the session Bearer token. The token rides the `Authorization` header (not a
    /// cookie), so no credentialed-CORS is needed.
    fn console_cors(&self) -> CorsLayer {
        let domain = self
            .public_host
            .strip_prefix("storage.")
            .unwrap_or(&self.public_host);
        let origins = [
            format!("https://console.{domain}"),
            format!("https://{domain}"),
            format!("https://www.{domain}"),
            "http://localhost:3000".to_string(),
        ];
        let allow: Vec<HeaderValue> = origins.iter().filter_map(|o| o.parse().ok()).collect();
        CorsLayer::new()
            .allow_origin(allow)
            .allow_methods([
                Method::GET,
                Method::POST,
                Method::PUT,
                Method::DELETE,
                Method::OPTIONS,
            ])
            .allow_headers([header::AUTHORIZATION, header::CONTENT_TYPE])
            .max_age(Duration::from_secs(86400))
    }

    /// Authenticate a console (Bearer) request and resolve the OWNED project's store.
    /// Mirrors the SigV4 path's owner re-check and fails closed: a bad/absent token is
    /// 401; a project that is absent OR owned by a different tenant is 404 (never 403),
    /// so the API can't be used to probe another tenant's project ids. Returns the
    /// project's store entry, or a JSON error `Response` to return verbatim.
    // The Err is a ready-to-return `Response` (the file's pattern for fail-closed
    // handler helpers); boxing it would only churn the 7 call sites.
    #[allow(clippy::result_large_err)]
    fn console_auth(
        &self,
        headers: &HeaderMap,
        project_id: &str,
    ) -> std::result::Result<Arc<ProjectEntry>, Response> {
        let token = headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.strip_prefix("Bearer "))
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| json_error(StatusCode::UNAUTHORIZED, "missing bearer token"))?;
        let tenant = match self.control.authenticate(token) {
            Ok(Some(t)) => t,
            Ok(None) => return Err(json_error(StatusCode::UNAUTHORIZED, "invalid token")),
            Err(e) => {
                warn!(error = %e, "console: authenticate failed");
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "auth unavailable",
                ));
            }
        };
        match self.control.get_project(project_id) {
            Ok(Some(p)) if p.tenant_id.as_deref() == Some(tenant.id.as_str()) => {}
            Ok(_) => return Err(json_error(StatusCode::NOT_FOUND, "project not found")),
            Err(e) => {
                warn!(error = %e, "console: get_project failed");
                return Err(json_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "lookup failed",
                ));
            }
        }
        self.project_entry(project_id).map_err(|e| {
            warn!(project = %project_id, error = %e, "console: object store open failed");
            json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "object store unavailable",
            )
        })
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
        if map.len() >= PROJECT_CACHE_CAP
            && !map.contains_key(project_id)
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
        let bytes = match tokio::task::spawn_blocking(move || {
            jkbase_common::storage::project_storage_bytes(&dd, &pid)
        })
        .await
        {
            Ok(b) => b,
            // Fail CLOSED on a walk task failure (symmetric with the count walk below),
            // rather than adopt bytes=0 and let writes slip the byte cap.
            Err(e) => {
                warn!(project = %project_id, error = %e, "object store byte walk task failed");
                return Err(s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "quota check temporarily unavailable",
                ));
            }
        };
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
    /// the write and held until the next authoritative TTL re-walk, which resets it to
    /// the on-disk figures. This is a SOFT cap bounded by the TTL: a write that reserves
    /// while a concurrent re-walk is in flight can have its reservation reset before its
    /// bytes land in `base`, so a tenant's own concurrent writes can briefly overshoot
    /// by up to what lands within one ≤TTL window; the next walk reconciles it.
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
        let projected_bytes = u
            .base_bytes
            .saturating_add(u.reserved_bytes)
            .saturating_add(len);
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
            let projected_objs = u
                .base_objects
                .saturating_add(u.reserved_objects)
                .saturating_add(1);
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
        let projected = u
            .base_buckets
            .saturating_add(u.reserved_buckets)
            .saturating_add(1);
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
        // The bucket is the first path segment (empty for the bucket-list root); the
        // `Origin` (if any) drives CORS stamping on the way out.
        let bucket = path
            .trim_start_matches('/')
            .split('/')
            .next()
            .unwrap_or("")
            .to_string();
        let origin = headers.get("origin").cloned();

        // --- 0. CORS preflight is ANONYMOUS (browsers never sign the OPTIONS): answer
        // it before the auth loop, resolving the target bucket's project from the
        // presigned credential (never verifying a signature). ---
        if method == "OPTIONS" {
            return self.handle_preflight(&bucket, &query, &headers).await;
        }

        let mut auth = Err("anonymous requests are not allowed".to_string());
        for host in self.host_candidates() {
            let lookup = |akid: &str| {
                self.control
                    .lookup_access_key(akid)
                    .ok()
                    .flatten()
                    .map(|k| k.secret_key)
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

        // --- 2b. Per-bucket CORS config CRUD (`?cors` subresource on `/{bucket}`).
        // Intercept BEFORE the quota logic below so a `PUT /{bucket}?cors` isn't mistaken
        // for a bucket create. Authenticated (owner-only) like any other S3 op. ---
        if !path_has_key(&path) && query.iter().any(|(k, _)| k == "cors") {
            return self.handle_bucket_cors(&method, &bucket, &entry, req).await;
        }

        let quota = self.control.get_quota(&project_id).unwrap_or(DEFAULT_QUOTA);

        // --- 3a. Cap bucket COUNT at create (PUT /{bucket}) via a lock-held reservation. ---
        let mut bucket_reserved = false;
        if is_bucket_create(&method, &path) {
            // Idempotent re-create of an EXISTING bucket must reach the engine (409
            // BucketAlreadyExists), NOT consume a reservation and report 409
            // TooManyBuckets when already at the bucket cap (residual #3).
            let bucket = path.trim_start_matches('/').split('/').next().unwrap_or("");
            if !entry.store.bucket_exists(bucket).await.unwrap_or(false) {
                if let Some(resp) = self.reserve_bucket(&entry, &project_id, &quota).await {
                    return resp;
                }
                bucket_reserved = true;
            }
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

        // --- 3c. Gate byte-adding writes against the storage + object-count caps, NET
        // of any object being overwritten: a re-PUT of an existing key adds no new
        // object and only its size DELTA in bytes, so the common "re-PUT same key"
        // pattern can't false-trip the cap. `reservation` = (reserved_bytes, +object?)
        // for credit-back; `body_cap` always caps the stream at the FULL declared length
        // (the unsigned Content-Length) regardless of the net reservation. ---
        let mut reservation: Option<(u64, bool)> = None;
        let mut body_cap: Option<u64> = None;
        if is_object_write(&method, &path) {
            let len = match write_len(&req) {
                Some(l) => l,
                None => {
                    return s3_error(
                        StatusCode::LENGTH_REQUIRED,
                        "MissingContentLength",
                        "object writes require a Content-Length",
                    );
                }
            };
            body_cap = Some(len);
            if is_upload_part(&query) {
                // A part adds bytes but is not (yet) a new object.
                if let Some(resp) = self
                    .refresh_and_reserve(&entry, &project_id, len, false, &quota)
                    .await
                {
                    return resp;
                }
                reservation = Some((len, false));
            } else {
                // Plain PUT: reserve only the NET delta vs any existing object at the key.
                let existing = match object_key(&path) {
                    Some((b, k)) => entry.store.object_size(b, k).await.ok().flatten(),
                    None => None,
                };
                let adds_object = existing.is_none();
                let net_bytes = len.saturating_sub(existing.unwrap_or(0));
                if let Some(resp) = self
                    .refresh_and_reserve(&entry, &project_id, net_bytes, adds_object, &quota)
                    .await
                {
                    return resp;
                }
                reservation = Some((net_bytes, adds_object));
            }
        } else if is_complete_multipart(&method, &query) {
            // CompleteMultipart materializes one object (its bytes were counted as
            // parts); an overwrite of an existing key adds no new object.
            let adds_object = match object_key(&path) {
                Some((b, k)) => entry.store.object_size(b, k).await.ok().flatten().is_none(),
                None => true,
            };
            if let Some(resp) = self
                .refresh_and_reserve(&entry, &project_id, 0, adds_object, &quota)
                .await
            {
                return resp;
            }
            reservation = Some((0, adds_object));
        }

        // --- 4. Serve from the project's own store. Route on the SAME canonical path
        // the signature covered (re-encode the verified, pct-decoded path) so a crafted
        // `%2F` can't sign one key yet route another. Cap the body to the FULL declared
        // length: it is NOT a signed header and the engine streams to EOF, so without
        // this a client could declare 1 byte and stream unbounded onto the shared disk.
        // Exceeding the cap errors the body mid-stream → the engine aborts the write.
        let req = set_canonical_path(req, &path);
        let req = match body_cap {
            // Cap at the FULL declared length, INCLUDING 0: a write that declares
            // Content-Length: 0 (reserving nothing) but then streams bytes must be
            // aborted, not allowed to write unbounded onto the shared disk.
            Some(len) => limit_body(req, len),
            None => req,
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
        if method == "DELETE" && resp.status().is_success() {
            // A successful DELETE freed something — an object/AbortMultipartUpload
            // (bytes + object count) OR a bucket (bucket count). Re-walk on the next
            // request so the freed capacity is credited promptly, not after the TTL.
            // (Previously only object deletes invalidated; a bucket delete left the
            // bucket count stale until the next ≤TTL re-walk — residual #2.)
            self.invalidate_usage_sample(&entry);
        }

        // --- 6. Stamp CORS onto the ACTUAL response when the request carried an Origin
        // the bucket's policy allows. Both auth paths (SigV4 header + presigned) converge
        // here, so this covers simple GETs (no preflight) and the real request after a
        // preflight, incl. error responses (so the browser can read a 404). ---
        let mut resp = resp;
        if let Some(origin) = &origin
            && let Ok(Some(cfg)) = entry.store.get_bucket_cors(&bucket).await
            && let Some(grant) = cfg.match_actual(origin, &method)
        {
            apply_actual_cors(resp.headers_mut(), &grant);
        }
        resp
    }

    /// Answer a browser CORS preflight. Anonymous by design: we resolve WHICH bucket's
    /// (browser-facing, non-secret) policy applies from the presigned credential's
    /// access-key id — never verifying a signature (browsers can't sign the OPTIONS) and
    /// never touching object bytes. Fails closed (403, no `Access-Control-*`) on any
    /// miss, so the browser blocks the real request.
    async fn handle_preflight(
        &self,
        bucket: &str,
        query: &[(String, String)],
        headers: &HashMap<String, String>,
    ) -> Response {
        // A real preflight carries Origin + Access-Control-Request-Method; a bare OPTIONS
        // is just an unauthenticated request → 403 like the fallback would give.
        let (Some(origin), Some(req_method)) = (
            headers.get("origin"),
            headers.get("access-control-request-method"),
        ) else {
            return s3_access_denied("anonymous requests are not allowed");
        };
        let Some(store) = self.resolve_store_for_preflight(query) else {
            return preflight_denied();
        };
        let cfg = match store.get_bucket_cors(bucket).await {
            Ok(Some(c)) => c,
            _ => return preflight_denied(),
        };
        let req_headers: Vec<String> = headers
            .get("access-control-request-headers")
            .map(|s| {
                s.split(',')
                    .map(|h| h.trim().to_string())
                    .filter(|h| !h.is_empty())
                    .collect()
            })
            .unwrap_or_default();
        match cfg.match_preflight(origin, req_method, &req_headers) {
            Some(grant) => preflight_response(&grant),
            None => preflight_denied(),
        }
    }

    /// Resolve the project store a preflight targets from the presigned
    /// `X-Amz-Credential` (`<AKID>/<date>/<region>/<service>/aws4_request`). Applies the
    /// SAME owner re-bind as the authed path so an orphaned key can't resolve to a
    /// project a different tenant now owns. `None` (⇒ deny) when unresolvable.
    fn resolve_store_for_preflight(&self, query: &[(String, String)]) -> Option<Arc<ObjectStore>> {
        let cred = query.iter().find(|(k, _)| k == "X-Amz-Credential")?;
        let akid = cred.1.split('/').next()?;
        let key = self.control.lookup_access_key(akid).ok().flatten()?;
        match self.control.get_project(&key.project_id) {
            Ok(Some(p)) if p.tenant_id.as_deref() == Some(key.tenant_id.as_str()) => {}
            _ => return None,
        }
        self.project_entry(&key.project_id)
            .ok()
            .map(|e| e.store.clone())
    }

    /// CRUD the bucket's CORS config via the S3 `?cors` subresource. Owner-authenticated
    /// upstream; here we just parse/serialize the S3 XML and hit the engine.
    async fn handle_bucket_cors(
        &self,
        method: &str,
        bucket: &str,
        entry: &ProjectEntry,
        req: Request,
    ) -> Response {
        // Reject a malformed bucket name up front with a proper 400 (using the engine's
        // own validator, so the rule can't drift) instead of a 500 buried in the
        // read/delete error arms below.
        if let Err(ObjectError::InvalidBucketName(_)) = entry.store.bucket_exists(bucket).await {
            return s3_error(
                StatusCode::BAD_REQUEST,
                "InvalidBucketName",
                "the specified bucket is not valid",
            );
        }
        match method {
            "GET" => match entry.store.get_bucket_cors(bucket).await {
                Ok(Some(cfg)) => xml_ok(cors_config_to_xml(&cfg)),
                Ok(None) => s3_error(
                    StatusCode::NOT_FOUND,
                    "NoSuchCORSConfiguration",
                    "the CORS configuration does not exist",
                ),
                Err(_) => s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "could not read CORS configuration",
                ),
            },
            "PUT" => {
                if !entry.store.bucket_exists(bucket).await.unwrap_or(false) {
                    return s3_error(
                        StatusCode::NOT_FOUND,
                        "NoSuchBucket",
                        "the specified bucket does not exist",
                    );
                }
                let bytes = match axum::body::to_bytes(req.into_body(), 64 * 1024).await {
                    Ok(b) => b,
                    Err(_) => {
                        return s3_error(
                            StatusCode::BAD_REQUEST,
                            "MalformedXML",
                            "CORS configuration body too large or unreadable",
                        );
                    }
                };
                let cfg = match parse_cors_config_xml(&String::from_utf8_lossy(&bytes)) {
                    Ok(c) => c,
                    Err(e) => return s3_error(StatusCode::BAD_REQUEST, "MalformedXML", &e),
                };
                match entry.store.put_bucket_cors(bucket, &cfg).await {
                    Ok(()) => StatusCode::OK.into_response(),
                    Err(_) => s3_error(
                        StatusCode::INTERNAL_SERVER_ERROR,
                        "InternalError",
                        "could not store CORS configuration",
                    ),
                }
            }
            "DELETE" => match entry.store.delete_bucket_cors(bucket).await {
                Ok(()) => StatusCode::NO_CONTENT.into_response(),
                Err(_) => s3_error(
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "InternalError",
                    "could not delete CORS configuration",
                ),
            },
            _ => s3_error(
                StatusCode::METHOD_NOT_ALLOWED,
                "MethodNotAllowed",
                "method not allowed on the ?cors subresource",
            ),
        }
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

// ============================================================================
// Console object API (`/_console/*`) — Bearer-authenticated, owner-scoped, JSON.
// Reuses this service's per-project store isolation + quota machinery; the control
// plane never touches the store. Errors are JSON (`{"error": ...}`) to match the
// control plane's shape so the console's `api()` helper reads them uniformly.
// ============================================================================

fn json_error(status: StatusCode, msg: &str) -> Response {
    (status, Json(serde_json::json!({ "error": msg }))).into_response()
}

/// 500 for an unexpected engine error: log the detail server-side, return a generic
/// body. Avoids echoing internal error strings (e.g. `CorruptMeta(<key>)`, raw IO
/// errors) back over the wire.
fn console_internal(op: &str, e: impl std::fmt::Display) -> Response {
    warn!(op, error = %e, "console object api: internal error");
    json_error(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

/// Convert a quota-reservation `Response` (built as S3 XML by the shared helpers)
/// into the console's JSON error shape, preserving the status.
fn reservation_json_error(resp: Response) -> Response {
    let status = resp.status();
    let msg = match status {
        StatusCode::CONFLICT => "bucket quota exceeded",
        StatusCode::INSUFFICIENT_STORAGE => "storage or object-count quota exceeded",
        _ => "quota check temporarily unavailable",
    };
    json_error(status, msg)
}

/// Reduce an object key to a safe `Content-Disposition` filename: basename only,
/// with anything outside a conservative allowlist replaced by `_`, so a crafted key
/// can never inject CR/LF or quotes into the response header.
fn sanitize_filename(key: &str) -> String {
    let base = key.rsplit('/').next().unwrap_or(key);
    let cleaned: String = base
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ' ' | '(' | ')') {
                c
            } else {
                '_'
            }
        })
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        "download".to_string()
    } else {
        trimmed.to_string()
    }
}

#[derive(serde::Deserialize)]
struct CreateBucketReq {
    name: String,
}

async fn console_list_buckets(
    State(svc): State<Arc<ObjectStoreService>>,
    Path(id): Path<String>,
    headers: HeaderMap,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match entry.store.list_buckets().await {
        Ok(buckets) => Json(serde_json::json!({
            "buckets": buckets.into_iter()
                .map(|name| serde_json::json!({ "name": name }))
                .collect::<Vec<_>>(),
        }))
        .into_response(),
        Err(e) => console_internal("object api", e),
    }
}

async fn console_create_bucket(
    State(svc): State<Arc<ObjectStoreService>>,
    Path(id): Path<String>,
    headers: HeaderMap,
    Json(req): Json<CreateBucketReq>,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let name = req.name.trim().to_string();
    let quota = svc.control.get_quota(&id).unwrap_or(DEFAULT_QUOTA);
    // Reserve the bucket slot under the per-project lock (closes the create race).
    // Skip the reservation for an idempotent re-create of an EXISTING bucket, so it
    // returns 409 BucketAlreadyExists from the engine instead of 409 TooManyBuckets
    // when at the cap (residual #3).
    let mut reserved = false;
    if !entry.store.bucket_exists(&name).await.unwrap_or(false) {
        if let Some(resp) = svc.reserve_bucket(&entry, &id, &quota).await {
            return reservation_json_error(resp);
        }
        reserved = true;
    }
    let res = entry.store.create_bucket(&name).await;
    if res.is_err() && reserved {
        svc.release_bucket_reservation(&entry);
    }
    match res {
        Ok(()) => (
            StatusCode::CREATED,
            Json(serde_json::json!({ "name": name })),
        )
            .into_response(),
        Err(ObjectError::BucketAlreadyExists(_)) => {
            json_error(StatusCode::CONFLICT, "bucket already exists")
        }
        Err(ObjectError::InvalidBucketName(_)) => json_error(
            StatusCode::BAD_REQUEST,
            "invalid bucket name (3–63 chars: lowercase letters, digits, hyphens)",
        ),
        Err(e) => console_internal("object api", e),
    }
}

async fn console_delete_bucket(
    State(svc): State<Arc<ObjectStoreService>>,
    Path((id, bucket)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    match entry.store.delete_bucket(&bucket).await {
        Ok(()) => {
            svc.invalidate_usage_sample(&entry); // a freed bucket: re-walk next request
            StatusCode::NO_CONTENT.into_response()
        }
        Err(ObjectError::BucketNotEmpty(_)) => json_error(StatusCode::CONFLICT, "bucket not empty"),
        Err(ObjectError::NoSuchBucket(_)) => json_error(StatusCode::NOT_FOUND, "bucket not found"),
        Err(ObjectError::InvalidBucketName(_)) => {
            json_error(StatusCode::BAD_REQUEST, "invalid bucket name")
        }
        Err(e) => console_internal("object api", e),
    }
}

async fn console_list_objects(
    State(svc): State<Arc<ObjectStoreService>>,
    Path((id, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let prefix = q.get("prefix").map(String::as_str).unwrap_or("");
    // Default to folder-style "/" folding; an explicit empty delimiter means "flat".
    let delim = q.get("delimiter").map(String::as_str).unwrap_or("/");
    let delimiter = if delim.is_empty() { None } else { Some(delim) };
    let token = q.get("token").map(String::as_str).filter(|s| !s.is_empty());
    let max_keys = q
        .get("max_keys")
        .and_then(|s| s.parse::<usize>().ok())
        .unwrap_or(100);
    match entry
        .store
        .list_v2(&bucket, prefix, delimiter, token, max_keys)
        .await
    {
        Ok(page) => Json(serde_json::json!({
            "prefixes": page.common_prefixes,
            "objects": page.objects.iter().map(|m| serde_json::json!({
                "key": m.key,
                "size": m.size,
                "etag": m.etag,
                "content_type": m.content_type,
                "last_modified": m.last_modified,
            })).collect::<Vec<_>>(),
            "is_truncated": page.is_truncated,
            "next_token": page.next_continuation_token,
        }))
        .into_response(),
        Err(ObjectError::NoSuchBucket(_)) => json_error(StatusCode::NOT_FOUND, "bucket not found"),
        Err(ObjectError::InvalidBucketName(_)) => {
            json_error(StatusCode::BAD_REQUEST, "invalid bucket name")
        }
        Err(e) => console_internal("object api", e),
    }
}

async fn console_get_object(
    State(svc): State<Arc<ObjectStoreService>>,
    Path((id, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let key = match q.get("key").map(String::as_str).filter(|s| !s.is_empty()) {
        Some(k) => k,
        None => return json_error(StatusCode::BAD_REQUEST, "missing key"),
    };
    let download = matches!(
        q.get("download").map(String::as_str),
        Some("1") | Some("true")
    );
    match entry.store.get_object(&bucket, key).await {
        Ok((meta, file)) => {
            let disp = if download {
                format!("attachment; filename=\"{}\"", sanitize_filename(key))
            } else {
                "inline".to_string()
            };
            let parts: [(header::HeaderName, String); 4] = [
                (header::CONTENT_TYPE, meta.content_type.clone()),
                (header::CONTENT_LENGTH, meta.size.to_string()),
                (header::ETAG, format!("\"{}\"", meta.etag)),
                (header::CONTENT_DISPOSITION, disp),
            ];
            (parts, Body::from_stream(ReaderStream::new(file))).into_response()
        }
        Err(ObjectError::NoSuchKey(_)) | Err(ObjectError::NoSuchBucket(_)) => {
            json_error(StatusCode::NOT_FOUND, "not found")
        }
        Err(ObjectError::InvalidKey(_)) | Err(ObjectError::InvalidBucketName(_)) => {
            json_error(StatusCode::BAD_REQUEST, "invalid request")
        }
        Err(e) => console_internal("object api", e),
    }
}

async fn console_put_object(
    State(svc): State<Arc<ObjectStoreService>>,
    Path((id, bucket)): Path<(String, String)>,
    req: Request,
) -> Response {
    let entry = match svc.console_auth(req.headers(), &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let key = match parse_query(req.uri().query().unwrap_or(""))
        .into_iter()
        .find(|(k, _)| k == "key")
        .map(|(_, v)| v)
        .filter(|s| !s.is_empty())
    {
        Some(k) => k,
        None => return json_error(StatusCode::BAD_REQUEST, "missing key"),
    };
    // A declared length is required to gate the byte quota AND cap the streamed body.
    let len = match write_len(&req) {
        Some(l) => l,
        None => {
            return json_error(
                StatusCode::LENGTH_REQUIRED,
                "upload requires a Content-Length",
            );
        }
    };
    let content_type = req
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    let quota = svc.control.get_quota(&id).unwrap_or(DEFAULT_QUOTA);
    // Reserve only the NET delta vs any object already at this key (a re-upload adds
    // no new object and only its size delta), mirroring the SigV4 write path.
    let existing = entry.store.object_size(&bucket, &key).await.ok().flatten();
    let adds_object = existing.is_none();
    let net_bytes = len.saturating_sub(existing.unwrap_or(0));
    if let Some(resp) = svc
        .refresh_and_reserve(&entry, &id, net_bytes, adds_object, &quota)
        .await
    {
        return reservation_json_error(resp);
    }
    // Cap the body at the declared length, INCLUDING 0: a client must not declare a
    // small (or zero) Content-Length — reserving little or nothing against the byte
    // quota — and then stream unbounded onto the shared disk. Exceeding the cap
    // aborts the write; a genuine 0-byte object (empty body) still succeeds.
    let req = limit_body(req, len);
    let reader = StreamReader::new(
        req.into_body()
            .into_data_stream()
            .map_err(std::io::Error::other),
    );
    match entry
        .store
        .put_object_capped(&bucket, &key, reader, &content_type, None, None, Some(len))
        .await
    {
        Ok(meta) => (
            StatusCode::OK,
            Json(serde_json::json!({ "key": meta.key, "size": meta.size, "etag": meta.etag })),
        )
            .into_response(),
        Err(e) => {
            svc.release_reservation(&entry, net_bytes, adds_object);
            match e {
                ObjectError::NoSuchBucket(_) => {
                    json_error(StatusCode::NOT_FOUND, "bucket not found")
                }
                ObjectError::InvalidKey(_) => json_error(StatusCode::BAD_REQUEST, "invalid key"),
                ObjectError::Timeout(_) => {
                    json_error(StatusCode::REQUEST_TIMEOUT, "upload timed out")
                }
                _ => console_internal("put_object", e),
            }
        }
    }
}

async fn console_delete_object(
    State(svc): State<Arc<ObjectStoreService>>,
    Path((id, bucket)): Path<(String, String)>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let entry = match svc.console_auth(&headers, &id) {
        Ok(e) => e,
        Err(r) => return r,
    };
    let key = match q.get("key").map(String::as_str).filter(|s| !s.is_empty()) {
        Some(k) => k,
        None => return json_error(StatusCode::BAD_REQUEST, "missing key"),
    };
    match entry.store.delete_object(&bucket, key).await {
        Ok(()) => {
            svc.invalidate_usage_sample(&entry); // freed space/object: re-walk next request
            StatusCode::NO_CONTENT.into_response()
        }
        Err(ObjectError::NoSuchBucket(_)) => json_error(StatusCode::NOT_FOUND, "bucket not found"),
        Err(ObjectError::InvalidKey(_)) => json_error(StatusCode::BAD_REQUEST, "invalid key"),
        Err(e) => console_internal("object api", e),
    }
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

/// Split a decoded object path `/{bucket}/{key}` into its parts (key may contain
/// `/`). `None` for the bucket-list root or a bucket-only path.
fn object_key(path: &str) -> Option<(&str, &str)> {
    let (bucket, key) = path.trim_start_matches('/').split_once('/')?;
    if bucket.is_empty() || key.is_empty() {
        return None;
    }
    Some((bucket, key))
}

/// A valid project id = the slug the control plane mints (`[a-z0-9-]`, 1..=63). Used
/// both as the store-root path component (must never be empty → the shared parent)
/// and to skip junk dirs in the multipart sweeper.
fn is_valid_project_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A bucket create = `PUT /{bucket}` with no key segment.
fn is_bucket_create(method: &str, path: &str) -> bool {
    method == "PUT"
        && !path_has_key(path)
        && path
            .trim_start_matches('/')
            .split('/')
            .next()
            .is_some_and(|b| !b.is_empty())
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
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(b as char)
            }
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
        .filter_map(|(k, v)| {
            v.to_str()
                .ok()
                .map(|s| (k.as_str().to_lowercase(), s.to_string()))
        })
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
        // Decode `%XX` from the RAW BYTES — never slice the &str by byte index, or a
        // `%` sitting just before a multibyte UTF-8 char would panic on a non-char
        // boundary (an unauthenticated request hits this before SigV4).
        if b[i] == b'%' && i + 2 < b.len() {
            match (hex_nibble(b[i + 1]), hex_nibble(b[i + 2])) {
                (Some(hi), Some(lo)) => {
                    out.push((hi << 4) | lo);
                    i += 3;
                }
                _ => {
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

fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b - b'0'),
        b'a'..=b'f' => Some(b - b'a' + 10),
        b'A'..=b'F' => Some(b - b'A' + 10),
        _ => None,
    }
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xml_ok(body: String) -> Response {
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "application/xml")],
        body,
    )
        .into_response()
}

/// A denied preflight: 403 with NO `Access-Control-Allow-Origin`, so the browser
/// blocks the real request (the spec key is the header's absence, not the status).
fn preflight_denied() -> Response {
    (StatusCode::FORBIDDEN, Body::empty()).into_response()
}

fn preflight_response(grant: &cors::PreflightGrant) -> Response {
    let mut b = Response::builder()
        .status(StatusCode::NO_CONTENT)
        .header(header::ACCESS_CONTROL_ALLOW_ORIGIN, &grant.allow_origin)
        .header(header::ACCESS_CONTROL_ALLOW_METHODS, &grant.allow_methods);
    if let Some(h) = &grant.allow_headers {
        b = b.header(header::ACCESS_CONTROL_ALLOW_HEADERS, h);
    }
    if let Some(age) = grant.max_age {
        b = b.header(header::ACCESS_CONTROL_MAX_AGE, age.to_string());
    }
    if grant.vary_origin {
        b = b.header(header::VARY, "Origin");
    }
    b.body(Body::empty())
        .unwrap_or_else(|_| StatusCode::NO_CONTENT.into_response())
}

/// Stamp `Access-Control-Allow-Origin` / `-Expose-Headers` (+ `Vary: Origin`) onto an
/// actual response for a matched origin.
fn apply_actual_cors(h: &mut HeaderMap, grant: &cors::ActualGrant) {
    if let Ok(v) = HeaderValue::from_str(&grant.allow_origin) {
        h.insert(header::ACCESS_CONTROL_ALLOW_ORIGIN, v);
    }
    if let Some(exp) = &grant.expose_headers
        && let Ok(v) = HeaderValue::from_str(exp)
    {
        h.insert(header::ACCESS_CONTROL_EXPOSE_HEADERS, v);
    }
    if grant.vary_origin {
        append_vary_origin(h);
    }
}

/// Add `Origin` to `Vary` without clobbering an existing value (so caches key the
/// origin-specific `Access-Control-Allow-Origin` correctly).
fn append_vary_origin(h: &mut HeaderMap) {
    match h.get(header::VARY).and_then(|v| v.to_str().ok()) {
        Some(cur) if cur.to_ascii_lowercase().split(',').any(|p| p.trim() == "origin") => {}
        Some(cur) => {
            if let Ok(v) = HeaderValue::from_str(&format!("{cur}, Origin")) {
                h.insert(header::VARY, v);
            }
        }
        None => {
            h.insert(header::VARY, HeaderValue::from_static("Origin"));
        }
    }
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
                    method,
                    "storage.jkbase.app",
                    &path,
                    &[],
                    "UNSIGNED-PAYLOAD",
                    &akid,
                    &secret,
                    "us-east-1",
                    now_secs(),
                );
                let rb = client
                    .request(
                        reqwest::Method::from_bytes(method.as_bytes()).unwrap(),
                        format!("{base}{path}"),
                    )
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
        let anon = client
            .get(format!("{base}/photos/cat.txt"))
            .send()
            .await
            .unwrap();
        assert_eq!(anon.status().as_u16(), 403);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// On-box e2e of the Bearer CONSOLE object API over real TCP/HTTP. Proves the
    /// whole stack the browser drives: CORS preflight, Bearer auth, bucket create,
    /// streamed upload, delimiter folder listing + pagination, authenticated
    /// download (Content-Disposition), delete, and cross-tenant 404. `#[ignore]`
    /// because it binds a port; run with `--ignored`.
    #[tokio::test]
    #[ignore]
    async fn console_e2e_over_real_http() {
        let dir = tmp("console-e2e");
        let store = store_at(&dir);
        mk_project(&store, "proj-a", "tenant-a");
        mk_project(&store, "proj-b", "tenant-b");
        let tok_a = mk_tenant_token(&store, "tenant-a");
        let tok_b = mk_tenant_token(&store, "tenant-b");
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.jkbase.app".to_string(), // -> console origin https://console.jkbase.app
        ));
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            axum::serve(listener, svc.into_router()).await.unwrap();
        });
        let base = format!("http://{addr}");
        let c = reqwest::Client::new();
        let bget = |p: String, t: String| {
            let c = c.clone();
            let base = base.clone();
            async move {
                c.get(format!("{base}{p}"))
                    .bearer_auth(t)
                    .send()
                    .await
                    .unwrap()
            }
        };

        // CORS preflight from the console origin is allowed + echoes the origin.
        let pre = c
            .request(
                reqwest::Method::OPTIONS,
                format!("{base}/_console/projects/proj-a/buckets"),
            )
            .header("origin", "https://console.jkbase.app")
            .header("access-control-request-method", "POST")
            .header(
                "access-control-request-headers",
                "authorization,content-type",
            )
            .send()
            .await
            .unwrap();
        assert!(
            pre.status().is_success(),
            "preflight status {}",
            pre.status()
        );
        assert_eq!(
            pre.headers()
                .get("access-control-allow-origin")
                .and_then(|v| v.to_str().ok()),
            Some("https://console.jkbase.app"),
            "CORS must allow the console origin"
        );

        // No token -> 401.
        let r = c
            .get(format!("{base}/_console/projects/proj-a/buckets"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 401);

        // Create a bucket.
        let r = c
            .post(format!("{base}/_console/projects/proj-a/buckets"))
            .bearer_auth(&tok_a)
            .json(&serde_json::json!({ "name": "docs" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status().as_u16(), 201, "create bucket");

        // Streamed uploads: two under "a/", one at the root.
        for (key, body) in [
            ("a/1.txt", "hello"),
            ("a/2.txt", "world"),
            ("readme.txt", "top"),
        ] {
            let r = c
                .put(format!(
                    "{base}/_console/projects/proj-a/buckets/docs/object?key={key}"
                ))
                .bearer_auth(&tok_a)
                .header("content-type", "text/plain")
                .body(body)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status().as_u16(), 200, "upload {key}");
        }

        // Bucket list reflects the new bucket.
        let buckets = bget("/_console/projects/proj-a/buckets".into(), tok_a.clone())
            .await
            .json::<serde_json::Value>()
            .await
            .unwrap();
        assert_eq!(buckets["buckets"][0]["name"], "docs");

        // Folder listing at root: folder "a/" folded, "readme.txt" listed.
        let root = bget(
            "/_console/projects/proj-a/buckets/docs/objects".into(),
            tok_a.clone(),
        )
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
        assert_eq!(root["prefixes"][0], "a/");
        assert_eq!(root["objects"][0]["key"], "readme.txt");

        // Pagination over "a/": max_keys=1 -> truncated, token "a/1.txt".
        let p1 = bget(
            "/_console/projects/proj-a/buckets/docs/objects?prefix=a/&max_keys=1".into(),
            tok_a.clone(),
        )
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
        assert_eq!(p1["is_truncated"], true);
        assert_eq!(p1["next_token"], "a/1.txt");
        let p2 = bget(
            "/_console/projects/proj-a/buckets/docs/objects?prefix=a/&max_keys=1&token=a%2F1.txt"
                .into(),
            tok_a.clone(),
        )
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
        assert_eq!(p2["objects"][0]["key"], "a/2.txt");

        // Authenticated download with attachment disposition + body round-trip.
        let dl = bget(
            "/_console/projects/proj-a/buckets/docs/object?key=a%2F1.txt&download=1".into(),
            tok_a.clone(),
        )
        .await;
        assert_eq!(dl.status().as_u16(), 200);
        let cd = dl
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            cd.starts_with("attachment") && cd.contains("1.txt"),
            "disposition: {cd}"
        );
        assert_eq!(dl.text().await.unwrap(), "hello");

        // Cross-tenant: tenant-b's valid token must 404 on proj-a.
        let x = bget("/_console/projects/proj-a/buckets".into(), tok_b.clone()).await;
        assert_eq!(x.status().as_u16(), 404, "cross-tenant must 404");

        // Delete an object, then it's gone.
        let d = c
            .delete(format!(
                "{base}/_console/projects/proj-a/buckets/docs/object?key=a%2F1.txt"
            ))
            .bearer_auth(&tok_a)
            .send()
            .await
            .unwrap();
        assert_eq!(d.status().as_u16(), 204);
        let after = bget(
            "/_console/projects/proj-a/buckets/docs/objects?prefix=a/".into(),
            tok_a.clone(),
        )
        .await
        .json::<serde_json::Value>()
        .await
        .unwrap();
        let keys: Vec<String> = after["objects"]
            .as_array()
            .unwrap()
            .iter()
            .map(|o| o["key"].as_str().unwrap().to_string())
            .collect();
        assert_eq!(keys, vec!["a/2.txt".to_string()], "deleted object gone");

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
            method,
            "storage.test",
            path,
            &[],
            "UNSIGNED-PAYLOAD",
            akid,
            secret,
            "us-east-1",
            now_secs(),
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

    /// SigV4 header-signed request carrying query params (e.g. the `?cors` subresource).
    fn signed_q(
        method: &str,
        path: &str,
        query: &[(&str, &str)],
        akid: &str,
        secret: &str,
        body: &str,
    ) -> Request {
        let q: Vec<(String, String)> = query
            .iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect();
        let (auth, amzd) = sigv4::sign_header(
            method,
            "storage.test",
            path,
            &q,
            "UNSIGNED-PAYLOAD",
            akid,
            secret,
            "us-east-1",
            now_secs(),
        );
        let qs = query
            .iter()
            .map(|(k, v)| {
                if v.is_empty() {
                    (*k).to_string()
                } else {
                    format!("{k}={v}")
                }
            })
            .collect::<Vec<_>>()
            .join("&");
        let uri = if qs.is_empty() {
            path.to_string()
        } else {
            format!("{path}?{qs}")
        };
        HttpRequest::builder()
            .method(method)
            .uri(uri)
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("content-length", body.len().to_string())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    const CORS_XML: &str = "<CORSConfiguration><CORSRule>\
        <AllowedOrigin>https://app.example.com</AllowedOrigin>\
        <AllowedMethod>GET</AllowedMethod><AllowedMethod>PUT</AllowedMethod>\
        <AllowedHeader>*</AllowedHeader>\
        <ExposeHeader>ETag</ExposeHeader><ExposeHeader>Content-Range</ExposeHeader>\
        <MaxAgeSeconds>3600</MaxAgeSeconds></CORSRule></CORSConfiguration>";

    fn hdr(resp: &Response, name: &str) -> Option<String> {
        resp.headers()
            .get(name)
            .and_then(|v| v.to_str().ok())
            .map(String::from)
    }

    #[tokio::test]
    async fn cors_crud_preflight_and_actual_stamping() {
        let dir = tmp("cors");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let k = store.create_access_key("proj", "tenant-x", "t").unwrap();
        let (akid, secret) = (k.access_key_id.clone(), k.secret_key.clone());
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();

        // Bucket + an object to fetch.
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &akid, &secret, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt/asset.bin", &akid, &secret, "hello"))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // PutBucketCors on a bucket that doesn't exist -> 404 (not a bucket-create).
        assert_eq!(
            app.clone()
                .oneshot(signed_q("PUT", "/nope", &[("cors", "")], &akid, &secret, CORS_XML))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );

        // PutBucketCors -> GetBucketCors round-trips.
        assert_eq!(
            app.clone()
                .oneshot(signed_q("PUT", "/bkt", &[("cors", "")], &akid, &secret, CORS_XML))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed_q("GET", "/bkt", &[("cors", "")], &akid, &secret, ""))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("https://app.example.com"), "got: {body}");

        // Preflight from an ALLOWED origin (anonymous OPTIONS to the presigned URL) -> 204 + ACAO.
        let presigned = sigv4::presign(
            "GET",
            "storage.test",
            "/bkt/asset.bin",
            &akid,
            &secret,
            "us-east-1",
            3600,
            now_secs(),
        );
        let preflight = |origin: &str| {
            HttpRequest::builder()
                .method("OPTIONS")
                .uri(presigned.clone())
                .header("host", "storage.test")
                .header("origin", origin)
                .header("access-control-request-method", "GET")
                .body(Body::empty())
                .unwrap()
        };
        let ok = app
            .clone()
            .oneshot(preflight("https://app.example.com"))
            .await
            .unwrap();
        assert_eq!(ok.status(), StatusCode::NO_CONTENT);
        assert_eq!(
            hdr(&ok, "access-control-allow-origin").as_deref(),
            Some("https://app.example.com")
        );
        assert!(hdr(&ok, "access-control-allow-methods").is_some());

        // Preflight from a DISALLOWED origin -> denied, no ACAO (browser blocks it).
        let bad = app
            .clone()
            .oneshot(preflight("https://evil.example"))
            .await
            .unwrap();
        assert_eq!(bad.status(), StatusCode::FORBIDDEN);
        assert!(hdr(&bad, "access-control-allow-origin").is_none());

        // Actual (SigV4) GET carrying an allowed Origin -> ACAO + exposed headers.
        let mut req = signed("GET", "/bkt/asset.bin", &akid, &secret, "");
        req.headers_mut()
            .insert("origin", HeaderValue::from_static("https://app.example.com"));
        let got = app.clone().oneshot(req).await.unwrap();
        assert_eq!(got.status(), StatusCode::OK);
        assert_eq!(
            hdr(&got, "access-control-allow-origin").as_deref(),
            Some("https://app.example.com")
        );
        let expose = hdr(&got, "access-control-expose-headers").unwrap_or_default();
        assert!(expose.contains("ETag"), "expose was: {expose}");
        assert_eq!(hdr(&got, "vary").as_deref(), Some("Origin"));

        // DeleteBucketCors -> subsequent GET is 404, and preflight now denies.
        assert_eq!(
            app.clone()
                .oneshot(signed_q("DELETE", "/bkt", &[("cors", "")], &akid, &secret, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(signed_q("GET", "/bkt", &[("cors", "")], &akid, &secret, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
        assert_eq!(
            app.clone()
                .oneshot(preflight("https://app.example.com"))
                .await
                .unwrap()
                .status(),
            StatusCode::FORBIDDEN
        );
    }

    #[tokio::test]
    async fn range_and_conditional_get_over_sigv4() {
        let dir = tmp("range");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let k = store.create_access_key("proj", "tenant-x", "t").unwrap();
        let (akid, secret) = (k.access_key_id.clone(), k.secret_key.clone());
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();

        app.clone()
            .oneshot(signed("PUT", "/bkt", &akid, &secret, ""))
            .await
            .unwrap();
        // PUT with Cache-Control (not a signed header — added after signing).
        let mut put = signed("PUT", "/bkt/obj", &akid, &secret, "0123456789");
        put.headers_mut().insert(
            "cache-control",
            HeaderValue::from_static("public, max-age=60"),
        );
        assert_eq!(app.clone().oneshot(put).await.unwrap().status(), StatusCode::OK);

        // Ranged SigV4 GET -> 206 + Content-Range, and Cache-Control echoed.
        let mut get = signed("GET", "/bkt/obj", &akid, &secret, "");
        get.headers_mut()
            .insert("range", HeaderValue::from_static("bytes=2-5"));
        let r = app.clone().oneshot(get).await.unwrap();
        assert_eq!(r.status(), StatusCode::PARTIAL_CONTENT);
        assert_eq!(hdr(&r, "content-range").as_deref(), Some("bytes 2-5/10"));
        assert_eq!(hdr(&r, "accept-ranges").as_deref(), Some("bytes"));
        assert_eq!(
            hdr(&r, "cache-control").as_deref(),
            Some("public, max-age=60")
        );
        let (st, body) = status_body(r).await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT);
        assert_eq!(body, "2345");

        // Conditional SigV4 GET: If-None-Match with the etag -> 304.
        let head = app
            .clone()
            .oneshot(signed("HEAD", "/bkt/obj", &akid, &secret, ""))
            .await
            .unwrap();
        let etag = hdr(&head, "etag").unwrap();
        let mut cond = signed("GET", "/bkt/obj", &akid, &secret, "");
        cond.headers_mut()
            .insert("if-none-match", HeaderValue::from_str(&etag).unwrap());
        assert_eq!(
            app.clone().oneshot(cond).await.unwrap().status(),
            StatusCode::NOT_MODIFIED
        );
    }

    #[tokio::test]
    async fn cors_config_is_tenant_isolated() {
        // tenant-b hitting the same bucket NAME via ?cors resolves to ITS OWN project
        // store, never tenant-a's config.
        let dir = tmp("cors-iso");
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

        // tenant-a: bucket + CORS config.
        app.clone()
            .oneshot(signed("PUT", "/shared", &a.access_key_id, &a.secret_key, ""))
            .await
            .unwrap();
        assert_eq!(
            app.clone()
                .oneshot(signed_q(
                    "PUT",
                    "/shared",
                    &[("cors", "")],
                    &a.access_key_id,
                    &a.secret_key,
                    CORS_XML
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // tenant-b GET ?cors on the same name -> 404 (its own store has no such config).
        assert_eq!(
            app.clone()
                .oneshot(signed_q(
                    "GET",
                    "/shared",
                    &[("cors", "")],
                    &b.access_key_id,
                    &b.secret_key,
                    ""
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NOT_FOUND
        );
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
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/hello.txt",
                    &a.access_key_id,
                    &a.secret_key,
                    "hi there"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed(
                    "GET",
                    "/bkt/hello.txt",
                    &a.access_key_id,
                    &a.secret_key,
                    "",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(body, "hi there");

        // tenant-b signs validly but has its OWN store root -> /bkt doesn't exist for it.
        let r = app
            .clone()
            .oneshot(signed(
                "GET",
                "/bkt/hello.txt",
                &b.access_key_id,
                &b.secret_key,
                "",
            ))
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NOT_FOUND); // NoSuchBucket in b's namespace

        // Wrong secret -> 403.
        let r = app
            .clone()
            .oneshot(signed(
                "GET",
                "/bkt/hello.txt",
                &a.access_key_id,
                "WRONG",
                "",
            ))
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
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        let r = app
            .clone()
            .oneshot(signed("GET", "/bkt/x", &k.access_key_id, &k.secret_key, ""))
            .await
            .unwrap();
        assert_eq!(
            r.status(),
            StatusCode::FORBIDDEN,
            "orphaned key must not work after owner change"
        );
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
        std::fs::create_dir_all(
            data.join("objectstore")
                .join("victim-proj")
                .join("secret-bkt"),
        )
        .unwrap();
        let bad = store.create_access_key("", "attacker", "evil").unwrap(); // empty project id
        let svc = Arc::new(ObjectStoreService::new(
            data,
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();

        // GET / would, without the guard, list the shared root (every project id).
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed("GET", "/", &bad.access_key_id, &bad.secret_key, ""))
                .await
                .unwrap(),
        )
        .await;
        assert_ne!(st, StatusCode::OK, "empty-project key must not succeed");
        assert!(
            !body.contains("victim-proj"),
            "must not leak other projects' ids"
        );
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
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Declare length 2 but send 100 bytes.
        let (auth, amzd) = sigv4::sign_header(
            "PUT",
            "storage.test",
            "/bkt/k",
            &[],
            "UNSIGNED-PAYLOAD",
            &a.access_key_id,
            &a.secret_key,
            "us-east-1",
            now_secs(),
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
            app.clone()
                .oneshot(signed("GET", "/bkt/k", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            gst != StatusCode::OK || gbody.len() <= 2,
            "must not store beyond the reservation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn signed_zero_length_declared_then_streamed_is_capped() {
        // SigV4 path: declaring Content-Length: 0 (reserving nothing) then streaming
        // bytes must be capped by the 0-byte body limit, not written to the disk.
        let dir = tmp("cl0");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let (auth, amzd) = sigv4::sign_header(
            "PUT",
            "storage.test",
            "/bkt/k",
            &[],
            "UNSIGNED-PAYLOAD",
            &a.access_key_id,
            &a.secret_key,
            "us-east-1",
            now_secs(),
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/bkt/k")
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("content-length", "0")
            .body(Body::from("x".repeat(100)))
            .unwrap();
        let st = app.clone().oneshot(req).await.unwrap().status();
        assert_ne!(st, StatusCode::OK, "CL:0 + streamed body must not succeed");
        let (gst, gbody) = status_body(
            app.clone()
                .oneshot(signed("GET", "/bkt/k", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            gst != StatusCode::OK || gbody.is_empty(),
            "must not store beyond the 0-byte reservation"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_without_content_length_is_rejected() {
        let dir = tmp("nolen");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        // Sign a PUT but strip content-length -> 411 (can't dodge the quota gate).
        let (auth, amzd) = sigv4::sign_header(
            "PUT",
            "storage.test",
            "/bkt/k",
            &[],
            "UNSIGNED-PAYLOAD",
            &a.access_key_id,
            &a.secret_key,
            "us-east-1",
            now_secs(),
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
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::LENGTH_REQUIRED
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn write_with_decoded_content_length_is_accepted() {
        // The SDK's streaming uploads (put_object_stream / upload_part_stream) go out
        // chunked with NO Content-Length but DO set x-amz-decoded-content-length. Prove the
        // front's write_len() picks that up so the write passes the 411 gate and stores —
        // the production-front proof for the streaming fix (the bare-engine e2e can't show
        // this, as it has no 411 gate).
        let dir = tmp("declen");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();

        // Create the bucket (signed; this one carries Content-Length naturally).
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );

        // A write with NO Content-Length, length declared only via x-amz-decoded-content-length.
        let body = "streamed-bytes"; // 14 bytes
        let (auth, amzd) = sigv4::sign_header(
            "PUT",
            "storage.test",
            "/bkt/s.bin",
            &[],
            "UNSIGNED-PAYLOAD",
            &a.access_key_id,
            &a.secret_key,
            "us-east-1",
            now_secs(),
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/bkt/s.bin")
            .header("host", "storage.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .header("x-amz-decoded-content-length", body.len().to_string())
            .body(Body::from(body))
            .unwrap();
        assert_eq!(
            app.clone().oneshot(req).await.unwrap().status(),
            StatusCode::OK
        );

        // It reads back intact.
        let (st, got) = status_body(
            app.clone()
                .oneshot(signed(
                    "GET",
                    "/bkt/s.bin",
                    &a.access_key_id,
                    &a.secret_key,
                    "",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(got, body);

        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- console (Bearer) object API ---------------------------------------

    /// Create a tenant + a session API token; returns the raw bearer token string.
    fn mk_tenant_token(store: &Store, tenant_id: &str) -> String {
        use jkbase_control::auth::{self, ApiToken, Tenant};
        store
            .create_tenant(&Tenant {
                id: tenant_id.to_string(),
                email: format!("{tenant_id}@test"),
                password_hash: None,
                created_at: 0,
            })
            .unwrap();
        let raw = format!("tok-{tenant_id}-secret");
        store
            .save_api_token(&ApiToken {
                id: format!("tid-{tenant_id}"),
                tenant_id: tenant_id.to_string(),
                name: "console".to_string(),
                token_hash: auth::hash_token(&raw).unwrap(),
                created_at: 0,
            })
            .unwrap();
        raw
    }

    fn bearer(method: &str, path: &str, token: &str, ct: &str, body: &str) -> Request {
        HttpRequest::builder()
            .method(method)
            .uri(path)
            .header("authorization", format!("Bearer {token}"))
            .header("content-type", ct)
            .header("content-length", body.len().to_string())
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn console_browser_round_trip_pagination_and_isolation() {
        let dir = tmp("console");
        let store = store_at(&dir);
        mk_project(&store, "proj-a", "tenant-a");
        mk_project(&store, "proj-b", "tenant-b");
        let tok_a = mk_tenant_token(&store, "tenant-a");
        let tok_b = mk_tenant_token(&store, "tenant-b");
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        let go = |req: Request| {
            let app = app.clone();
            async move { status_body(app.oneshot(req).await.unwrap()).await }
        };

        // No token -> 401.
        let (st, _) = status_body(
            app.clone()
                .oneshot(
                    HttpRequest::get("/_console/projects/proj-a/buckets")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::UNAUTHORIZED);

        // Bad bucket name -> 400 (and quota slot is released, not leaked).
        let (st, _) = go(bearer(
            "POST",
            "/_console/projects/proj-a/buckets",
            &tok_a,
            "application/json",
            "{\"name\":\"AB\"}",
        ))
        .await;
        assert_eq!(st, StatusCode::BAD_REQUEST);

        // Create bucket "docs".
        let (st, _) = go(bearer(
            "POST",
            "/_console/projects/proj-a/buckets",
            &tok_a,
            "application/json",
            "{\"name\":\"docs\"}",
        ))
        .await;
        assert_eq!(st, StatusCode::CREATED);

        // Upload three objects: two under folder "a/", one at the root.
        for (key, body) in [
            ("a/1.txt", "hello"),
            ("a/2.txt", "world"),
            ("readme.txt", "top"),
        ] {
            let (st, _) = go(bearer(
                "PUT",
                &format!("/_console/projects/proj-a/buckets/docs/object?key={key}"),
                &tok_a,
                "text/plain",
                body,
            ))
            .await;
            assert_eq!(st, StatusCode::OK, "upload {key}");
        }

        // List root with delimiter "/" -> folder "a/" folded, "readme.txt" listed.
        let (st, body) = go(bearer(
            "GET",
            "/_console/projects/proj-a/buckets/docs/objects",
            &tok_a,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("\"a/\""), "prefixes should hold a/: {body}");
        assert!(
            body.contains("readme.txt"),
            "objects should hold readme.txt: {body}"
        );
        assert!(
            !body.contains("a/1.txt"),
            "nested keys must be folded, not listed: {body}"
        );

        // Descend into "a/" -> its two members, no sub-folders.
        let (st, body) = go(bearer(
            "GET",
            "/_console/projects/proj-a/buckets/docs/objects?prefix=a/",
            &tok_a,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(
            body.contains("a/1.txt") && body.contains("a/2.txt"),
            "{body}"
        );

        // Pagination: max_keys=1 over "a/" pages cleanly via next_token.
        let (st, body) = go(bearer(
            "GET",
            "/_console/projects/proj-a/buckets/docs/objects?prefix=a/&max_keys=1",
            &tok_a,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::OK);
        assert!(body.contains("\"is_truncated\":true"), "{body}");
        assert!(body.contains("\"next_token\":\"a/1.txt\""), "{body}");

        // Download an object (content round-trips; Content-Disposition is attachment).
        let resp = app
            .clone()
            .oneshot(bearer(
                "GET",
                "/_console/projects/proj-a/buckets/docs/object?key=a/1.txt&download=1",
                &tok_a,
                "",
                "",
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let cd = resp
            .headers()
            .get("content-disposition")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_string();
        assert!(
            cd.starts_with("attachment") && cd.contains("1.txt"),
            "cd: {cd}"
        );
        let (_, dl) = status_body(resp).await;
        assert_eq!(dl, "hello");

        // Cross-tenant: tenant-b's valid token must NOT reach proj-a (404, not 403).
        let (st, _) = go(bearer(
            "GET",
            "/_console/projects/proj-a/buckets",
            &tok_b,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::NOT_FOUND, "cross-tenant access must 404");

        // Delete is gated + bucket-non-empty is refused, then cleanup succeeds.
        let (st, _) = go(bearer(
            "DELETE",
            "/_console/projects/proj-a/buckets/docs",
            &tok_a,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::CONFLICT, "non-empty bucket delete must 409");

        for key in ["a/1.txt", "a/2.txt", "readme.txt"] {
            let (st, _) = go(bearer(
                "DELETE",
                &format!("/_console/projects/proj-a/buckets/docs/object?key={key}"),
                &tok_a,
                "",
                "",
            ))
            .await;
            assert_eq!(st, StatusCode::NO_CONTENT, "delete {key}");
        }
        let (st, _) = go(bearer(
            "DELETE",
            "/_console/projects/proj-a/buckets/docs",
            &tok_a,
            "",
            "",
        ))
        .await;
        assert_eq!(st, StatusCode::NO_CONTENT, "empty bucket deletes");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn console_zero_length_declared_then_streamed_is_capped() {
        // A console upload that declares Content-Length: 0 (reserving nothing) but
        // streams bytes must be aborted by the 0-byte body cap — not written
        // unbounded onto the shared disk. A genuine 0-byte object still succeeds.
        let dir = tmp("console-cl0");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let tok = mk_tenant_token(&store, "tenant-x");
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            status_body(
                app.clone()
                    .oneshot(bearer(
                        "POST",
                        "/_console/projects/proj/buckets",
                        &tok,
                        "application/json",
                        "{\"name\":\"bkt\"}"
                    ))
                    .await
                    .unwrap()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        // Declare 0 but stream 100 bytes -> aborted (non-2xx), object not stored as 100B.
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/_console/projects/proj/buckets/bkt/object?key=k")
            .header("authorization", format!("Bearer {tok}"))
            .header("content-length", "0")
            .body(Body::from("x".repeat(100)))
            .unwrap();
        let st = app.clone().oneshot(req).await.unwrap().status();
        assert_ne!(st, StatusCode::OK, "CL:0 + streamed body must not succeed");
        let (gst, gbody) = status_body(
            app.clone()
                .oneshot(bearer(
                    "GET",
                    "/_console/projects/proj/buckets/bkt/object?key=k",
                    &tok,
                    "",
                    "",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert!(
            gst != StatusCode::OK || gbody.is_empty(),
            "must not store beyond the 0-byte reservation"
        );

        // A genuine empty (0-byte) object still uploads fine.
        let ok = HttpRequest::builder()
            .method("PUT")
            .uri("/_console/projects/proj/buckets/bkt/object?key=empty")
            .header("authorization", format!("Bearer {tok}"))
            .header("content-length", "0")
            .body(Body::empty())
            .unwrap();
        assert_eq!(
            app.oneshot(ok).await.unwrap().status(),
            StatusCode::OK,
            "empty object should upload"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn console_put_without_content_length_is_rejected() {
        // The byte-quota gate needs a declared length; a console upload without one
        // must 411 (can't dodge the cap), mirroring the SigV4 path.
        let dir = tmp("console-nolen");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let tok = mk_tenant_token(&store, "tenant-x");
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        // Pre-create the bucket so we reach the length check, not a 404.
        assert_eq!(
            status_body(
                app.clone()
                    .oneshot(bearer(
                        "POST",
                        "/_console/projects/proj/buckets",
                        &tok,
                        "application/json",
                        "{\"name\":\"bkt\"}"
                    ))
                    .await
                    .unwrap()
            )
            .await
            .0,
            StatusCode::CREATED
        );
        let req = HttpRequest::builder()
            .method("PUT")
            .uri("/_console/projects/proj/buckets/bkt/object?key=k")
            .header("authorization", format!("Bearer {tok}"))
            .body(Body::from("data"))
            .unwrap();
        assert_eq!(
            app.oneshot(req).await.unwrap().status(),
            StatusCode::LENGTH_REQUIRED
        );
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
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/aaa", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed("PUT", "/bbb", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert!(body.contains("TooManyBuckets"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn idempotent_recreate_at_cap_is_bucket_exists_not_quota() {
        // Residual #3: re-creating an EXISTING bucket while at the bucket cap must hit
        // the engine's idempotency (409 BucketAlreadyExists), not be misreported as
        // 409 TooManyBuckets by the reservation gate.
        let dir = tmp("recreate");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let mut q = DEFAULT_QUOTA;
        q.max_buckets = 1;
        store.set_quota("proj", &q).unwrap();
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/aaa", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Re-PUT the same bucket while at the cap: engine idempotency, not the quota gate.
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed("PUT", "/aaa", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::CONFLICT);
        assert!(
            body.contains("BucketAlreadyExists"),
            "expected BucketAlreadyExists, got: {body}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bucket_delete_credits_count_promptly() {
        // Residual #2: a successful bucket DELETE invalidates the usage sample so the
        // freed slot is credited on the NEXT request, not after the ≤TTL re-walk.
        let dir = tmp("bktcredit");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let mut q = DEFAULT_QUOTA;
        q.max_buckets = 1;
        store.set_quota("proj", &q).unwrap();
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        // At the cap with one bucket; a second create is refused.
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/aaa", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bbb", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::CONFLICT
        );
        // Delete frees the slot; the re-create must succeed IMMEDIATELY (no TTL wait).
        assert_eq!(
            app.clone()
                .oneshot(signed(
                    "DELETE",
                    "/aaa",
                    &a.access_key_id,
                    &a.secret_key,
                    ""
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::NO_CONTENT
        );
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bbb", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "freed bucket slot must be credited without waiting out the TTL"
        );
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
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/o1",
                    &a.access_key_id,
                    &a.secret_key,
                    "x"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // A second object exceeds the count cap within the TTL window -> 507.
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/o2",
                    &a.access_key_id,
                    &a.secret_key,
                    "y",
                ))
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::INSUFFICIENT_STORAGE);
        assert!(body.contains("TooManyObjects"), "{body}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn object_overwrite_does_not_trip_count_cap() {
        // Regression for the merge-gate HIGH: a re-PUT of an EXISTING key adds no
        // object, so it must not false-trip max_objects even at the cap — while a
        // genuinely new key still does.
        let dir = tmp("objoverwrite");
        let store = store_at(&dir);
        mk_project(&store, "proj", "tenant-x");
        let mut q = DEFAULT_QUOTA;
        q.max_objects = 1;
        store.set_quota("proj", &q).unwrap();
        let a = store.create_access_key("proj", "tenant-x", "").unwrap();
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        assert_eq!(
            app.clone()
                .oneshot(signed("PUT", "/bkt", &a.access_key_id, &a.secret_key, ""))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // First write of the key consumes the 1-object budget.
        assert_eq!(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/o1",
                    &a.access_key_id,
                    &a.secret_key,
                    "v1"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK
        );
        // Overwriting the SAME key (even with a larger body) must still succeed.
        assert_eq!(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/o1",
                    &a.access_key_id,
                    &a.secret_key,
                    "v2-longer"
                ))
                .await
                .unwrap()
                .status(),
            StatusCode::OK,
            "re-PUT of an existing key must not trip the object-count cap"
        );
        // A genuinely new key still trips the cap.
        let (st, body) = status_body(
            app.clone()
                .oneshot(signed(
                    "PUT",
                    "/bkt/o2",
                    &a.access_key_id,
                    &a.secret_key,
                    "x",
                ))
                .await
                .unwrap(),
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
        let svc = Arc::new(ObjectStoreService::new(
            dir.join("data"),
            store,
            "storage.test".to_string(),
        ));
        let app = svc.into_router();
        let (auth, amzd) = sigv4::sign_header(
            "PUT",
            "storage.test:443",
            "/bkt",
            &[],
            "UNSIGNED-PAYLOAD",
            &a.access_key_id,
            &a.secret_key,
            "us-east-1",
            now_secs(),
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
    fn pct_decode_is_byte_safe() {
        // Regression: `pct_decode("%a€")` slices "%a€"[1..3] in the old code, cutting
        // mid-`€` (a non-char boundary) → panic. The byte-safe decoder must NOT panic
        // and must treat a `%` before a multibyte char literally. Valid escapes still
        // decode; incomplete escapes pass through.
        assert_eq!(pct_decode("/a%2Fb"), "/a/b");
        assert_eq!(pct_decode("%E2%82%AC"), "€");
        assert_eq!(pct_decode("%a€"), "%a€"); // % then non-hex multibyte → literal, no panic
        assert_eq!(pct_decode("%\u{20ac}x"), "%\u{20ac}x");
        assert_eq!(pct_decode("%zz"), "%zz");
        assert_eq!(pct_decode("trailing%"), "trailing%");
        assert_eq!(pct_decode("trailing%4"), "trailing%4");
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
