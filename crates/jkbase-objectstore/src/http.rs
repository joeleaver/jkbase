//! S3-compatible HTTP surface over [`ObjectStore`]. Path-style routing
//! (`/{bucket}/{key}`), streamed object bodies (never buffered), and S3-style XML
//! for listings + errors.
//!
//! This layer is **unauthenticated** — the productized server uses `router(store)`
//! with per-project filesystem-root isolation as the sole tenant boundary.

use crate::{ObjectError, ObjectMeta, ObjectStore};
use axum::{
    Router,
    body::Body,
    extract::{Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use futures_util::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio_util::io::{ReaderStream, StreamReader};

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
    let sha256 = extract_content_sha256(&headers);
    if let (Some(uid), Some(pn)) = (q.get("uploadId"), q.get("partNumber")) {
        let part_number: u32 = match pn.parse() {
            Ok(n) => n,
            Err(_) => return s3_error(ObjectError::InvalidArgument(format!("partNumber {pn}"))),
        };
        let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
        return match store.upload_part(&bucket, uid, part_number, reader, sha256.as_deref()).await {
            Ok(etag) => ([(header::ETAG, quoted(&etag))], StatusCode::OK).into_response(),
            Err(e) => s3_error(e),
        };
    }
    // Plain object put — stream the body straight to disk, never buffered.
    let content_type = content_type_of(&headers);
    let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    match store.put_object(&bucket, &key, reader, &content_type, sha256.as_deref()).await {
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
) -> Response {
    match store.create_bucket(&bucket).await {
        Ok(()) => StatusCode::OK.into_response(),
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

async fn list_buckets(State(store): State<Arc<ObjectStore>>) -> Response {
    match store.list_buckets().await {
        Ok(names) => {
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

/// GET /{bucket} — either ListObjects or ListMultipartUploads (`?uploads`).
/// Supports V1 (`?marker`) and V2 (`?continuation-token` / `?start-after`)
/// pagination styles and `?max-keys` (default 1000, clamped 1–1000).
async fn list_objects(
    State(store): State<Arc<ObjectStore>>,
    Path(bucket): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    // Branch on ?uploads = ListMultipartUploads.
    if q.contains_key("uploads") {
        return list_multipart_uploads_handler(store, bucket).await;
    }

    let prefix = q.get("prefix").map(String::as_str).unwrap_or("");
    // V2 continuation-token takes priority; fall back to V1 marker.
    let start_after = q
        .get("continuation-token")
        .or_else(|| q.get("start-after"))
        .or_else(|| q.get("marker"))
        .map(String::as_str);
    let max_keys: usize = q
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000);

    match store.list_objects(&bucket, prefix, start_after, max_keys).await {
        Ok(page) => {
            let key_count = page.objects.len();
            let mut x = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Name>{}</Name><Prefix>{}</Prefix>\
                 <MaxKeys>{max_keys}</MaxKeys>\
                 <KeyCount>{key_count}</KeyCount>\
                 <IsTruncated>{}</IsTruncated>",
                xml_escape(&bucket),
                xml_escape(prefix),
                page.is_truncated,
            );
            // Pagination tokens — emit both V1 and V2 forms when truncated.
            if let Some(ref tok) = page.next_continuation_token {
                x.push_str(&format!("<NextContinuationToken>{}</NextContinuationToken>", xml_escape(tok)));
                x.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(tok)));
            }
            // Echo the input tokens so V2 clients can round-trip.
            if let Some(ct) = q.get("continuation-token") {
                x.push_str(&format!("<ContinuationToken>{}</ContinuationToken>", xml_escape(ct)));
            }
            if let Some(sa) = q.get("start-after") {
                x.push_str(&format!("<StartAfter>{}</StartAfter>", xml_escape(sa)));
            }
            for m in page.objects {
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

/// ListMultipartUploads — returns pending uploads for the bucket.
async fn list_multipart_uploads_handler(store: Arc<ObjectStore>, bucket: String) -> Response {
    match store.list_multipart_uploads(&bucket).await {
        Ok(uploads) => {
            let mut x = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                 <ListMultipartUploadsResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                 <Bucket>{}</Bucket>",
                xml_escape(&bucket)
            );
            for u in uploads {
                x.push_str(&format!(
                    "<Upload><Key>{}</Key><UploadId>{}</UploadId><Initiated>{}</Initiated></Upload>",
                    xml_escape(&u.key),
                    xml_escape(&u.upload_id),
                    iso8601(u.initiated),
                ));
            }
            x.push_str("</ListMultipartUploadsResult>");
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

/// Extract `x-amz-content-sha256` only when it looks like a literal hex digest
/// (64 lowercase hex chars). Sentinel values like `UNSIGNED-PAYLOAD` and
/// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` are treated as absent (no body check).
fn extract_content_sha256(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("x-amz-content-sha256")?.to_str().ok()?;
    if v.len() == 64 && v.bytes().all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f')) {
        Some(v.to_string())
    } else {
        None
    }
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
        ObjectError::Timeout(_) => (StatusCode::REQUEST_TIMEOUT, "RequestTimeout"),
        ObjectError::ContentSha256Mismatch => (StatusCode::BAD_REQUEST, "XAmzContentSHA256Mismatch"),
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
    use std::sync::atomic::{AtomicU64, Ordering};
    use tower::ServiceExt; // oneshot

    static TMP: AtomicU64 = AtomicU64::new(0);

    fn store() -> (Arc<ObjectStore>, std::path::PathBuf) {
        let dir = std::env::temp_dir().join(format!("jkb-objhttp-{}", TMP.fetch_add(1, Ordering::Relaxed)));
        let _ = std::fs::remove_dir_all(&dir);
        (Arc::new(ObjectStore::open(&dir).unwrap()), dir)
    }

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

    #[tokio::test]
    async fn list_objects_pagination_over_http() {
        let (s, dir) = store();
        let app = router(s.clone());
        app.clone().oneshot(Request::put("/pg-bucket").body(Body::empty()).unwrap()).await.unwrap();
        for k in ["a", "b", "c", "d", "e"] {
            app.clone()
                .oneshot(Request::put(format!("/pg-bucket/{k}")).body(Body::from("x")).unwrap())
                .await
                .unwrap();
        }
        // First page of 2.
        let r = app
            .clone()
            .oneshot(Request::get("/pg-bucket?max-keys=2").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<NextContinuationToken>"));
        // Extract token.
        let tok_start = xml.find("<NextContinuationToken>").unwrap() + "<NextContinuationToken>".len();
        let tok_end = xml.find("</NextContinuationToken>").unwrap();
        let token = &xml[tok_start..tok_end];
        assert_eq!(token, "b");

        // Second page using continuation-token.
        let r = app
            .clone()
            .oneshot(
                Request::get(format!("/pg-bucket?max-keys=2&continuation-token={token}"))
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (_, _, xml2) = body_str(r).await;
        assert!(xml2.contains("<Key>c</Key>"));
        assert!(xml2.contains("<Key>d</Key>"));
        assert!(!xml2.contains("<Key>e</Key>")); // not on this page yet
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

        // ListMultipartUploads.
        let r = app
            .clone()
            .oneshot(Request::get("/mp-bucket?uploads").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(xml.contains("<UploadId>"));
        assert!(xml.contains("<Key>big.bin</Key>"));

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

    #[tokio::test]
    async fn sha256_header_binding_over_http() {
        use sha2::{Digest as Sha2Digest, Sha256};
        let (s, dir) = store();
        let app = router(s);
        app.clone().oneshot(Request::put("/sha-bucket").body(Body::empty()).unwrap()).await.unwrap();

        let body = b"payload bytes";
        let good_hash = format!("{:x}", Sha256::digest(body));
        // Correct hash -> 200.
        let r = app
            .clone()
            .oneshot(
                Request::put("/sha-bucket/obj")
                    .header("x-amz-content-sha256", &good_hash)
                    .body(Body::from(body.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        // Wrong hash (a valid 64-char hex, but wrong value) -> 400.
        let bad_hash = "a".repeat(64);
        let r = app
            .clone()
            .oneshot(
                Request::put("/sha-bucket/obj")
                    .header("x-amz-content-sha256", &bad_hash)
                    .body(Body::from(body.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::BAD_REQUEST);
        assert!(xml.contains("XAmzContentSHA256Mismatch"));

        // UNSIGNED-PAYLOAD sentinel -> no check, always 200.
        let r = app
            .clone()
            .oneshot(
                Request::put("/sha-bucket/obj")
                    .header("x-amz-content-sha256", "UNSIGNED-PAYLOAD")
                    .body(Body::from(body.as_slice()))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::OK);

        let _ = std::fs::remove_dir_all(&dir);
    }
}
