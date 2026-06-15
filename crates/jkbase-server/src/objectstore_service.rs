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
use jkbase_control::store::Store;
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

/// Mutable per-project usage accounting, guarded by its OWN lock so one project's
/// (potentially large) dir-walk never blocks another project's requests.
struct Usage {
    base_bytes: u64,
    sampled_at: Instant,
    reserved: u64,
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
        if project_id.is_empty()
            || project_id.len() > 63
            || !project_id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        {
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
                // Force a fresh walk on the first write (sampled "in the past").
                sampled_at: Instant::now()
                    .checked_sub(QUOTA_TTL)
                    .unwrap_or_else(Instant::now),
                reserved: 0,
            }),
        });
        map.insert(project_id.to_string(), entry.clone());
        Ok(entry)
    }

    /// Reserve `len` bytes against the project's storage cap. Returns `Some(error
    /// response)` if it would exceed the cap, else `None` (reserved). Fail-closed: the
    /// reservation is added BEFORE the write, deletes are not credited until the next
    /// TTL re-walk, and the base re-walk includes the just-written bytes — so
    /// concurrent writes within a window can't overshoot.
    fn reserve_quota(&self, entry: &ProjectEntry, project_id: &str, len: u64) -> Option<Response> {
        let cap = self
            .control
            .get_quota(project_id)
            .map(|q| q.storage_bytes_max)
            .unwrap_or(u64::MAX);
        let mut u = entry.usage.lock().unwrap();
        if u.sampled_at.elapsed() > QUOTA_TTL {
            u.base_bytes = jkbase_common::storage::project_storage_bytes(&self.data_dir, project_id);
            u.reserved = 0;
            u.sampled_at = Instant::now();
        }
        let projected = u.base_bytes.saturating_add(u.reserved).saturating_add(len);
        if projected > cap {
            return Some(s3_error(
                StatusCode::INSUFFICIENT_STORAGE,
                "QuotaExceeded",
                &format!("storage quota exceeded: would use {projected} bytes, cap is {cap}"),
            ));
        }
        u.reserved = u.reserved.saturating_add(len);
        None
    }

    async fn handle(&self, req: Request) -> Response {
        // --- 1. Authenticate (SigV4) against the CONFIGURED public host. ---
        let method = req.method().as_str().to_string();
        let path = pct_decode(req.uri().path());
        let query = parse_query(req.uri().query().unwrap_or(""));
        let now = now_secs();
        let lookup = |akid: &str| {
            self.control
                .lookup_access_key(akid)
                .ok()
                .flatten()
                .map(|k| k.secret_key)
        };

        let auth = if query.iter().any(|(k, _)| k == "X-Amz-Signature") {
            sigv4::verify_presigned(&method, &self.public_host, &path, &query, lookup, now)
        } else if let Some(a) = req
            .headers()
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
        {
            let headers = lower_headers(&req);
            sigv4::verify_header(&method, &self.public_host, &path, &query, &headers, a, lookup, now)
        } else {
            Err("anonymous requests are not allowed".to_string())
        };
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

        // --- 3. Gate byte-adding writes against the storage quota. ---
        let mut write_cap: Option<u64> = None;
        if is_object_write(&method, &path) {
            match write_len(&req) {
                Some(len) => {
                    if let Some(resp) = self.reserve_quota(&entry, &project_id, len) {
                        return resp;
                    }
                    write_cap = Some(len);
                }
                None => {
                    return s3_error(
                        StatusCode::LENGTH_REQUIRED,
                        "MissingContentLength",
                        "object writes require a Content-Length",
                    );
                }
            }
        }

        // --- 4. Serve from the project's own store (engine router, already authed). ---
        // Cap the bytes the engine will write to exactly the reserved amount. The
        // declared length (Content-Length / x-amz-decoded-content-length) is NOT a
        // signed SigV4 header and the engine streams to EOF, so without this a client
        // could reserve 1 byte and stream unbounded data onto the shared disk (which
        // also holds the control-plane db). Exceeding the cap errors the body
        // mid-stream, so the engine aborts the write.
        let req = match write_cap {
            Some(len) => limit_body(req, len),
            None => req,
        };
        let app = jkbase_objectstore::router(entry.store.clone());
        match app.oneshot(req).await {
            Ok(resp) => resp,
            Err(e) => match e {}, // Router error is Infallible
        }
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
}
