//! S3-compatible HTTP surface over [`ObjectStore`]. Path-style routing
//! (`/{bucket}/{key}`), streamed object bodies (never buffered), and S3-style XML
//! for listings + errors.
//!
//! This layer is **unauthenticated** on its own — tenant auth (SigV4) + bucket
//! ownership is a separate card and is expected to wrap this router as middleware.
//! Multipart upload + presigned URLs are the next slice of this card.

use crate::{Credentials, ObjectError, ObjectMeta, ObjectStore, sigv4};
use axum::{
    Extension, Router,
    body::Body,
    extract::{Path, Query, Request, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{Next, from_fn_with_state},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use futures_util::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};
use tokio_util::io::{ReaderStream, StreamReader};

/// The authenticated tenant, injected into request extensions by [`auth_layer`].
#[derive(Clone)]
pub struct Tenant(pub String);

/// Build the S3 router backed by `store`.
pub fn router(store: Arc<ObjectStore>) -> Router {
    Router::new()
        .route("/", get(list_buckets))
        .route(
            "/{bucket}",
            put(create_bucket)
                .delete(delete_bucket)
                .get(list_objects)
                .head(head_bucket),
        )
        .route(
            "/{bucket}/{*key}",
            put(put_dispatch)
                .post(post_dispatch)
                .get(get_object)
                .head(head_object)
                .delete(delete_dispatch),
        )
        .with_state(store)
}

/// The S3 router with SigV4 auth + per-tenant bucket-ownership enforcement.
pub fn router_with_auth(store: Arc<ObjectStore>, credentials: Arc<dyn Credentials>) -> Router {
    router(store.clone()).layer(from_fn_with_state(AuthState { store, credentials }, auth_mw))
}

#[derive(Clone)]
struct AuthState {
    store: Arc<ObjectStore>,
    credentials: Arc<dyn Credentials>,
}

/// Authenticate (SigV4 presigned or Authorization header) -> tenant, then enforce
/// that the bucket in the path is owned by that tenant. Injects [`Tenant`] for the
/// handlers (create claims ownership; list filters to owned).
async fn auth_mw(State(st): State<AuthState>, mut req: Request, next: Next) -> Response {
    let method = req.method().as_str().to_string();
    let path = pct_decode(req.uri().path());
    let query = parse_query(req.uri().query().unwrap_or(""));
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .to_string();
    let now = now_secs();

    let result = if query.iter().any(|(k, _)| k == "X-Amz-Signature") {
        sigv4::verify_presigned(
            &method,
            &host,
            &path,
            &query,
            |k| st.credentials.resolve(k).map(|c| c.secret_key),
            now,
        )
    } else if let Some(auth) = req.headers().get(header::AUTHORIZATION).and_then(|v| v.to_str().ok())
    {
        let headers: HashMap<String, String> = req
            .headers()
            .iter()
            .filter_map(|(k, v)| v.to_str().ok().map(|s| (k.as_str().to_lowercase(), s.to_string())))
            .collect();
        sigv4::verify_header(
            &method,
            &host,
            &path,
            &query,
            &headers,
            auth,
            |k| st.credentials.resolve(k).map(|c| c.secret_key),
            now,
        )
    } else {
        Err("anonymous requests are not allowed".to_string())
    };
    let access_key = match result {
        Ok(k) => k,
        Err(e) => return access_denied(&e),
    };
    let tenant = match st.credentials.resolve(&access_key) {
        Some(c) => c.tenant_id,
        None => return access_denied("unknown access key"),
    };

    // Per-tenant isolation: a bucket in the path (if any) must be unowned (a fresh
    // create claims it) or owned by this tenant.
    if let Some(bucket) = path_bucket(&path)
        && let Ok(Some(owner)) = st.store.bucket_owner(&bucket).await
        && owner != tenant
    {
        return access_denied("not the bucket owner");
    }

    req.extensions_mut().insert(Tenant(tenant));
    next.run(req).await
}

fn access_denied(msg: &str) -> Response {
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>AccessDenied</Code><Message>{}</Message></Error>",
        xml_escape(msg)
    );
    (StatusCode::FORBIDDEN, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

/// First path segment = the bucket; `/` (list all buckets) has none.
fn path_bucket(path: &str) -> Option<String> {
    path.trim_start_matches('/')
        .split('/')
        .next()
        .filter(|s| !s.is_empty())
        .map(|s| s.to_string())
}

/// Parse a query string into decoded (key, value) pairs.
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

// ---- objects --------------------------------------------------------------

/// PUT on the object path: a plain object put, or a multipart UploadPart when
/// `?uploadId=..&partNumber=..` is present.
async fn put_dispatch(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if let (Some(uid), Some(pn)) = (q.get("uploadId"), q.get("partNumber")) {
        let part_number: u32 = match pn.parse() {
            Ok(n) => n,
            Err(_) => return s3_error(ObjectError::InvalidArgument(format!("partNumber {pn}"))),
        };
        let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
        return match store.upload_part(&bucket, uid, part_number, reader).await {
            Ok(etag) => ([(header::ETAG, quoted(&etag))], StatusCode::OK).into_response(),
            Err(e) => s3_error(e),
        };
    }
    // Plain object put — stream the body straight to disk, never buffered.
    let content_type = content_type_of(&headers);
    let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    match store.put_object(&bucket, &key, reader, &content_type).await {
        Ok(meta) => ([(header::ETAG, quoted(&meta.etag))], StatusCode::OK).into_response(),
        Err(e) => s3_error(e),
    }
}

async fn get_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    match store.get_object(&bucket, &key).await {
        Ok((meta, file)) => (object_headers(&meta), Body::from_stream(ReaderStream::new(file))).into_response(),
        Err(e) => s3_error(e),
    }
}

async fn head_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    match store.head_object(&bucket, &key).await {
        Ok(meta) => object_headers(&meta).into_response(),
        Err(e) => s3_error(e),
    }
}

/// DELETE on the object path: AbortMultipartUpload when `?uploadId=..`, else a
/// plain object delete.
async fn delete_dispatch(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    if let Some(uid) = q.get("uploadId") {
        return match store.abort_multipart(&bucket, uid).await {
            Ok(()) => StatusCode::NO_CONTENT.into_response(),
            Err(e) => s3_error(e),
        };
    }
    match store.delete_object(&bucket, &key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => s3_error(e),
    }
}

/// POST on the object path: InitiateMultipartUpload (`?uploads`) or
/// CompleteMultipartUpload (`?uploadId=..`, body lists the parts in order).
async fn post_dispatch(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    if q.contains_key("uploads") {
        let content_type = content_type_of(&headers);
        return match store.create_multipart(&bucket, &key, &content_type).await {
            Ok(uid) => xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <InitiateMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Bucket>{}</Bucket><Key>{}</Key><UploadId>{}</UploadId>\
                 </InitiateMultipartUploadResult>",
                xml_escape(&bucket),
                xml_escape(&key),
                xml_escape(&uid)
            )),
            Err(e) => s3_error(e),
        };
    }
    if let Some(uid) = q.get("uploadId") {
        let bytes = match axum::body::to_bytes(body, 1 << 20).await {
            Ok(b) => b,
            Err(_) => return s3_error(ObjectError::InvalidArgument("parts list too large".into())),
        };
        let parts = parse_part_numbers(&String::from_utf8_lossy(&bytes));
        return match store.complete_multipart(&bucket, &key, uid, &parts).await {
            Ok(meta) => xml_ok(format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <CompleteMultipartUploadResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Bucket>{}</Bucket><Key>{}</Key><ETag>{}</ETag>\
                 </CompleteMultipartUploadResult>",
                xml_escape(&bucket),
                xml_escape(&key),
                xml_escape(&quoted(&meta.etag))
            )),
            Err(e) => s3_error(e),
        };
    }
    s3_error(ObjectError::InvalidArgument("missing ?uploads or ?uploadId".into()))
}

// ---- buckets --------------------------------------------------------------

async fn create_bucket(
    State(store): State<Arc<ObjectStore>>,
    Path(bucket): Path<String>,
    tenant: Option<Extension<Tenant>>,
) -> Response {
    match store.create_bucket(&bucket).await {
        Ok(()) => {
            // When authenticated, the creator owns the bucket (per-tenant isolation).
            if let Some(Extension(Tenant(t))) = tenant {
                let _ = store.set_bucket_owner(&bucket, &t).await;
            }
            StatusCode::OK.into_response()
        }
        Err(e) => s3_error(e),
    }
}

async fn delete_bucket(State(store): State<Arc<ObjectStore>>, Path(bucket): Path<String>) -> Response {
    match store.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => s3_error(e),
    }
}

async fn head_bucket(State(store): State<Arc<ObjectStore>>, Path(bucket): Path<String>) -> StatusCode {
    match store.bucket_exists(&bucket).await {
        Ok(true) => StatusCode::OK,
        Ok(false) => StatusCode::NOT_FOUND,
        Err(_) => StatusCode::BAD_REQUEST,
    }
}

async fn list_buckets(
    State(store): State<Arc<ObjectStore>>,
    tenant: Option<Extension<Tenant>>,
) -> Response {
    match store.list_buckets().await {
        Ok(all) => {
            // Authenticated: show only the tenant's own buckets. Unauthenticated
            // (the bare `router`): show all.
            let names = match &tenant {
                Some(Extension(Tenant(t))) => {
                    let mut owned = Vec::new();
                    for n in all {
                        if store.bucket_owner(&n).await.ok().flatten().as_deref() == Some(t.as_str()) {
                            owned.push(n);
                        }
                    }
                    owned
                }
                None => all,
            };
            let mut x = String::from(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <ListAllMyBucketsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\"><Buckets>",
            );
            for n in names {
                x.push_str(&format!("<Bucket><Name>{}</Name></Bucket>", xml_escape(&n)));
            }
            x.push_str("</Buckets></ListAllMyBucketsResult>");
            xml_ok(x)
        }
        Err(e) => s3_error(e),
    }
}

async fn list_objects(
    State(store): State<Arc<ObjectStore>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let prefix = q.get("prefix").map(String::as_str).unwrap_or("");
    match store.list_objects(&bucket, prefix).await {
        Ok(objs) => {
            let mut x = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Name>{}</Name><Prefix>{}</Prefix><KeyCount>{}</KeyCount><IsTruncated>false</IsTruncated>",
                xml_escape(&bucket),
                xml_escape(prefix),
                objs.len()
            );
            for m in objs {
                x.push_str(&format!(
                    "<Contents><Key>{}</Key><LastModified>{}</LastModified><ETag>{}</ETag><Size>{}</Size></Contents>",
                    xml_escape(&m.key),
                    iso8601(m.last_modified),
                    xml_escape(&quoted(&m.etag)),
                    m.size,
                ));
            }
            x.push_str("</ListBucketResult>");
            xml_ok(x)
        }
        Err(e) => s3_error(e),
    }
}

// ---- helpers --------------------------------------------------------------

fn quoted(etag: &str) -> String {
    format!("\"{etag}\"")
}

fn content_type_of(headers: &HeaderMap) -> String {
    headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string()
}

/// Extract `<PartNumber>N</PartNumber>` values from a CompleteMultipartUpload body
/// in document order (the parts are concatenated in that order).
fn parse_part_numbers(xml: &str) -> Vec<u32> {
    let mut out = Vec::new();
    let mut rest = xml;
    while let Some(i) = rest.find("<PartNumber>") {
        rest = &rest[i + "<PartNumber>".len()..];
        match rest.find("</PartNumber>") {
            Some(j) => {
                if let Ok(n) = rest[..j].trim().parse::<u32>() {
                    out.push(n);
                }
                rest = &rest[j..];
            }
            None => break,
        }
    }
    out
}

fn object_headers(meta: &ObjectMeta) -> [(header::HeaderName, String); 4] {
    [
        (header::CONTENT_TYPE, meta.content_type.clone()),
        (header::CONTENT_LENGTH, meta.size.to_string()),
        (header::ETAG, quoted(&meta.etag)),
        (header::LAST_MODIFIED, http_date(meta.last_modified)),
    ]
}

fn iso8601(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .format("%Y-%m-%dT%H:%M:%S.000Z")
        .to_string()
}

fn http_date(secs: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs as i64, 0)
        .unwrap_or_default()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string()
}

fn xml_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn xml_ok(body: String) -> Response {
    ([(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

/// Map a storage error onto the matching S3 error code + HTTP status + XML body.
fn s3_error(e: ObjectError) -> Response {
    let (status, code) = match &e {
        ObjectError::NoSuchBucket(_) => (StatusCode::NOT_FOUND, "NoSuchBucket"),
        ObjectError::NoSuchKey(_) => (StatusCode::NOT_FOUND, "NoSuchKey"),
        ObjectError::BucketAlreadyExists(_) => (StatusCode::CONFLICT, "BucketAlreadyExists"),
        ObjectError::BucketNotEmpty(_) => (StatusCode::CONFLICT, "BucketNotEmpty"),
        ObjectError::InvalidBucketName(_) => (StatusCode::BAD_REQUEST, "InvalidBucketName"),
        ObjectError::InvalidKey(_) => (StatusCode::BAD_REQUEST, "InvalidArgument"),
        ObjectError::NoSuchUpload(_) => (StatusCode::NOT_FOUND, "NoSuchUpload"),
        ObjectError::InvalidArgument(_) => (StatusCode::BAD_REQUEST, "InvalidArgument"),
        ObjectError::CorruptMeta(_) | ObjectError::Io(_) => {
            (StatusCode::INTERNAL_SERVER_ERROR, "InternalError")
        }
    };
    let body = format!(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?><Error><Code>{code}</Code><Message>{}</Message></Error>",
        xml_escape(&e.to_string())
    );
    (status, [(header::CONTENT_TYPE, "application/xml")], body).into_response()
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;
    use axum::http::Request;
    use md5::{Digest, Md5};
    use tower::ServiceExt; // oneshot

    fn store() -> (Arc<ObjectStore>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("jkb-objhttp-{}", TMP.fetch_add(1, ORD)));
        let _ = std::fs::remove_dir_all(&dir);
        (Arc::new(ObjectStore::open(&dir).unwrap()), dir)
    }
    use std::sync::atomic::{AtomicU64 as TMPK, Ordering as ORDK};
    static TMP: TMPK = TMPK::new(0);
    const ORD: ORDK = ORDK::Relaxed;

    async fn body_str(resp: Response) -> (StatusCode, HeaderMap, String) {
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (status, headers, String::from_utf8_lossy(&bytes).into_owned())
    }

    #[tokio::test]
    async fn put_get_delete_object_over_http() {
        let (s, dir) = store();
        let app = router(s);

        // Create bucket.
        let r = app
            .clone()
            .oneshot(Request::put("/my-bucket").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // PUT object.
        let r = app
            .clone()
            .oneshot(
                Request::put("/my-bucket/dir/obj.txt")
                    .header("content-type", "text/plain")
                    .body(Body::from("hello http"))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);
        let etag = r.headers().get("etag").unwrap().to_str().unwrap().to_string();
        assert_eq!(etag, format!("\"{:x}\"", Md5::digest(b"hello http")));

        // GET it back.
        let r = app
            .clone()
            .oneshot(Request::get("/my-bucket/dir/obj.txt").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, headers, text) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(headers.get("content-type").unwrap(), "text/plain");
        assert_eq!(text, "hello http");

        // GET missing -> 404 + S3 XML.
        let r = app
            .clone()
            .oneshot(Request::get("/my-bucket/nope").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, _, text) = body_str(r).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert!(text.contains("<Code>NoSuchKey</Code>"));

        // DELETE -> 204.
        let r = app
            .clone()
            .oneshot(Request::delete("/my-bucket/dir/obj.txt").body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_objects_returns_s3_xml() {
        let (s, dir) = store();
        let app = router(s);
        app.clone().oneshot(Request::put("/b-ucket").body(Body::empty()).unwrap()).await.unwrap();
        for k in ["img/a", "img/b", "doc/c"] {
            app.clone()
                .oneshot(Request::put(format!("/b-ucket/{k}")).body(Body::from("x")).unwrap())
                .await
                .unwrap();
        }
        let r = app
            .clone()
            .oneshot(Request::get("/b-ucket?prefix=img/").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(xml.contains("<Key>img/a</Key>"));
        assert!(xml.contains("<Key>img/b</Key>"));
        assert!(!xml.contains("doc/c"));
        assert!(xml.contains("<KeyCount>2</KeyCount>"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn between(s: &str, start: &str, end: &str) -> String {
        let i = s.find(start).unwrap() + start.len();
        let j = s[i..].find(end).unwrap();
        s[i..i + j].to_string()
    }

    #[tokio::test]
    async fn multipart_over_http() {
        let (s, dir) = store();
        let app = router(s);
        app.clone().oneshot(Request::put("/mp-bucket").body(Body::empty()).unwrap()).await.unwrap();

        // Initiate.
        let r = app
            .clone()
            .oneshot(Request::post("/mp-bucket/big.bin?uploads").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (_, _, xml) = body_str(r).await;
        let uid = between(&xml, "<UploadId>", "</UploadId>");

        // Upload two parts.
        for (n, data) in [(1, "AAAA"), (2, "BB")] {
            let r = app
                .clone()
                .oneshot(
                    Request::put(format!("/mp-bucket/big.bin?uploadId={uid}&partNumber={n}"))
                        .body(Body::from(data))
                        .unwrap(),
                )
                .await
                .unwrap();
            assert_eq!(r.status(), StatusCode::OK);
        }

        // Complete (parts listed in order).
        let complete = "<CompleteMultipartUpload>\
            <Part><PartNumber>1</PartNumber></Part>\
            <Part><PartNumber>2</PartNumber></Part></CompleteMultipartUpload>";
        let r = app
            .clone()
            .oneshot(
                Request::post(format!("/mp-bucket/big.bin?uploadId={uid}"))
                    .body(Body::from(complete))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(xml.contains("CompleteMultipartUploadResult"));

        // GET returns the concatenation.
        let r = app
            .clone()
            .oneshot(Request::get("/mp-bucket/big.bin").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (_, _, text) = body_str(r).await;
        assert_eq!(text, "AAAABB");
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn signed(method: &str, path: &str, key: &str, secret: &str, body: &str) -> Request<Body> {
        let (auth, amzd) = crate::sigv4::sign_header(
            method, "s3.test", path, &[], "UNSIGNED-PAYLOAD", key, secret, "us-east-1", now_secs(),
        );
        Request::builder()
            .method(method)
            .uri(path)
            .header("host", "s3.test")
            .header("authorization", auth)
            .header("x-amz-date", amzd)
            .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
            .body(Body::from(body.to_string()))
            .unwrap()
    }

    #[tokio::test]
    async fn auth_enforces_signature_and_bucket_ownership() {
        let (s, dir) = store();
        let creds = std::sync::Arc::new(
            crate::StaticCredentials::new()
                .with("AKIAA", "secretA", "tenant-a")
                .with("AKIAB", "secretB", "tenant-b"),
        );
        let app = router_with_auth(s, creds);

        // Unsigned request -> 403.
        let r = app.clone().oneshot(Request::put("/bkt").body(Body::empty()).unwrap()).await.unwrap();
        assert_eq!(r.status(), StatusCode::FORBIDDEN);

        // tenant-a creates a bucket + object (signed).
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt", "AKIAA", "secretA", "")).await.unwrap().status(),
            StatusCode::OK
        );
        assert_eq!(
            app.clone().oneshot(signed("PUT", "/bkt/k", "AKIAA", "secretA", "hi")).await.unwrap().status(),
            StatusCode::OK
        );
        // tenant-a reads its own object.
        assert_eq!(
            app.clone().oneshot(signed("GET", "/bkt/k", "AKIAA", "secretA", "")).await.unwrap().status(),
            StatusCode::OK
        );
        // tenant-b is signed-in but does not own the bucket -> 403.
        assert_eq!(
            app.clone().oneshot(signed("GET", "/bkt/k", "AKIAB", "secretB", "")).await.unwrap().status(),
            StatusCode::FORBIDDEN
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
