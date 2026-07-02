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
    http::{HeaderMap, HeaderValue, StatusCode, header},
    response::{IntoResponse, Response},
    routing::{get, put},
};
use futures_util::TryStreamExt;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
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
    let declared = declared_len(&headers);
    if let (Some(uid), Some(pn)) = (q.get("uploadId"), q.get("partNumber")) {
        let part_number: u32 = match pn.parse() {
            Ok(n) => n,
            Err(_) => return s3_error(ObjectError::InvalidArgument(format!("partNumber {pn}"))),
        };
        let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
        return match store
            .upload_part_capped(
                &bucket,
                uid,
                part_number,
                reader,
                sha256.as_deref(),
                declared,
            )
            .await
        {
            Ok(etag) => ([(header::ETAG, quoted(&etag))], StatusCode::OK).into_response(),
            Err(e) => s3_error(e),
        };
    }
    // Plain object put — stream the body straight to disk, never buffered.
    let content_type = content_type_of(&headers);
    let cache_control = cache_control_of(&headers);
    let reader = StreamReader::new(body.into_data_stream().map_err(std::io::Error::other));
    match store
        .put_object_capped(
            &bucket,
            &key,
            reader,
            &content_type,
            cache_control.as_deref(),
            sha256.as_deref(),
            declared,
        )
        .await
    {
        Ok(meta) => ([(header::ETAG, quoted(&meta.etag))], StatusCode::OK).into_response(),
        Err(e) => s3_error(e),
    }
}

async fn get_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    match store.get_object(&bucket, &key).await {
        Ok((meta, file)) => respond_object(meta, Some(file), &headers).await,
        Err(e) => s3_error(e),
    }
}

async fn head_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
) -> Response {
    match store.head_object(&bucket, &key).await {
        Ok(meta) => respond_object(meta, None, &headers).await,
        Err(e) => s3_error(e),
    }
}

/// Build a GET/HEAD response, honoring conditional GET (`If-None-Match` /
/// `If-Modified-Since` → 304) and a single `Range` (→ 206 / 416). `file` is `Some`
/// for GET (streamed body), `None` for HEAD. `Accept-Ranges: bytes` is always
/// advertised so clients know ranged reads are available.
async fn respond_object(
    meta: ObjectMeta,
    file: Option<tokio::fs::File>,
    headers: &HeaderMap,
) -> Response {
    // Conditional GET wins over Range: an unchanged resource is 304 regardless.
    if not_modified(&meta, headers) {
        return build_object_response(StatusCode::NOT_MODIFIED, &meta, None, None);
    }
    let total = meta.size;
    let Some(mut file) = file else {
        // HEAD: validators + Content-Length, no body.
        return build_object_response(StatusCode::OK, &meta, None, None);
    };
    match parse_range(headers.get(header::RANGE), total) {
        RangeOutcome::Full => {
            let body = Body::from_stream(ReaderStream::new(file));
            build_object_response(StatusCode::OK, &meta, Some(body), None)
        }
        RangeOutcome::Unsatisfiable => range_not_satisfiable(total),
        RangeOutcome::Partial { start, end } => {
            if file.seek(std::io::SeekFrom::Start(start)).await.is_err() {
                return s3_error(ObjectError::Io(std::io::Error::other("range seek failed")));
            }
            let len = end - start + 1;
            let body = Body::from_stream(ReaderStream::new(file.take(len)));
            build_object_response(
                StatusCode::PARTIAL_CONTENT,
                &meta,
                Some(body),
                Some((start, end, total)),
            )
        }
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
        let cache_control = cache_control_of(&headers);
        return match store
            .create_multipart(&bucket, &key, &content_type, cache_control.as_deref())
            .await
        {
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
    s3_error(ObjectError::InvalidArgument(
        "missing ?uploads or ?uploadId".into(),
    ))
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

async fn delete_bucket(
    State(store): State<Arc<ObjectStore>>,
    Path(bucket): Path<String>,
) -> Response {
    match store.delete_bucket(&bucket).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => s3_error(e),
    }
}

async fn head_bucket(
    State(store): State<Arc<ObjectStore>>,
    Path(bucket): Path<String>,
) -> StatusCode {
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
    // Clamp here too so the echoed <MaxKeys> reflects the EFFECTIVE value the engine
    // used (1..=1000), not the raw client-supplied number.
    let max_keys: usize = q
        .get("max-keys")
        .and_then(|s| s.parse().ok())
        .unwrap_or(1000)
        .clamp(1, 1000);

    // `?delimiter=` switches to V2 folding (CommonPrefixes), e.g. for the own-bucket binding's
    // `list-objects` and S3 clients that pass a delimiter.
    if let Some(delim) = q.get("delimiter").filter(|d| !d.is_empty()) {
        return match store
            .list_v2(&bucket, prefix, Some(delim), start_after, max_keys)
            .await
        {
            Ok(page) => {
                let mut x = format!(
                    "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\
                     <ListBucketResult xmlns=\"http://s3.amazonaws.com/doc/2006-03-01/\">\
                     <Name>{}</Name><Prefix>{}</Prefix><Delimiter>{}</Delimiter>\
                     <MaxKeys>{max_keys}</MaxKeys><KeyCount>{}</KeyCount>\
                     <IsTruncated>{}</IsTruncated>",
                    xml_escape(&bucket),
                    xml_escape(prefix),
                    xml_escape(delim),
                    page.objects.len() + page.common_prefixes.len(),
                    page.is_truncated,
                );
                if let Some(ref tok) = page.next_continuation_token {
                    x.push_str(&format!(
                        "<NextContinuationToken>{}</NextContinuationToken>",
                        xml_escape(tok)
                    ));
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
                for p in page.common_prefixes {
                    x.push_str(&format!(
                        "<CommonPrefixes><Prefix>{}</Prefix></CommonPrefixes>",
                        xml_escape(&p)
                    ));
                }
                x.push_str("</ListBucketResult>");
                xml_ok(x)
            }
            Err(e) => s3_error(e),
        };
    }

    match store
        .list_objects(&bucket, prefix, start_after, max_keys)
        .await
    {
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
                x.push_str(&format!(
                    "<NextContinuationToken>{}</NextContinuationToken>",
                    xml_escape(tok)
                ));
                x.push_str(&format!("<NextMarker>{}</NextMarker>", xml_escape(tok)));
            }
            // Echo the input tokens so V2 clients can round-trip.
            if let Some(ct) = q.get("continuation-token") {
                x.push_str(&format!(
                    "<ContinuationToken>{}</ContinuationToken>",
                    xml_escape(ct)
                ));
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

/// The declared body length, used only to size the upload deadline. Prefers
/// `x-amz-decoded-content-length` (the true payload size for aws-chunked, where
/// Content-Length is the larger framed size), falling back to Content-Length.
/// `None` when absent.
fn declared_len(headers: &HeaderMap) -> Option<u64> {
    headers
        .get("x-amz-decoded-content-length")
        .or_else(|| headers.get(header::CONTENT_LENGTH))
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.parse::<u64>().ok())
}

/// Extract `x-amz-content-sha256` only when it looks like a literal hex digest
/// (64 lowercase hex chars). Sentinel values like `UNSIGNED-PAYLOAD` and
/// `STREAMING-AWS4-HMAC-SHA256-PAYLOAD` are treated as absent (no body check).
fn extract_content_sha256(headers: &HeaderMap) -> Option<String> {
    let v = headers.get("x-amz-content-sha256")?.to_str().ok()?;
    // Accept upper- or lower-case hex (some header-auth SDKs send uppercase); the
    // engine lowercases before comparing. UNSIGNED-PAYLOAD / STREAMING-* fall through.
    if v.len() == 64 && v.bytes().all(|b| b.is_ascii_hexdigit()) {
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

fn content_type_of(headers: &HeaderMap) -> String {
    header_str(headers, header::CONTENT_TYPE).unwrap_or_else(|| "application/octet-stream".into())
}

/// Client `Cache-Control` to persist + echo (bounded so one absurd value can't bloat
/// the sidecar). `None` when absent/empty.
fn cache_control_of(headers: &HeaderMap) -> Option<String> {
    header_str(headers, header::CACHE_CONTROL).filter(|s| !s.is_empty() && s.len() <= 512)
}

fn header_str(headers: &HeaderMap, name: header::HeaderName) -> Option<String> {
    headers
        .get(name)
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
}

/// Assemble the object response. All representations carry the validators (ETag,
/// Last-Modified), `Cache-Control` (if set), and `Accept-Ranges: bytes`; a 206 adds
/// `Content-Range` + the partial `Content-Length`; a 200/HEAD adds the full
/// `Content-Length`; a 304 carries validators only (no body, no length).
fn build_object_response(
    status: StatusCode,
    meta: &ObjectMeta,
    body: Option<Body>,
    content_range: Option<(u64, u64, u64)>,
) -> Response {
    let mut b = Response::builder()
        .status(status)
        .header(header::CONTENT_TYPE, meta.content_type.as_str())
        .header(header::ETAG, quoted(&meta.etag))
        .header(header::LAST_MODIFIED, http_date(meta.last_modified))
        .header(header::ACCEPT_RANGES, "bytes");
    if let Some(cc) = &meta.cache_control {
        b = b.header(header::CACHE_CONTROL, cc.as_str());
    }
    match content_range {
        Some((start, end, total)) => {
            b = b
                .header(header::CONTENT_RANGE, format!("bytes {start}-{end}/{total}"))
                .header(header::CONTENT_LENGTH, (end - start + 1).to_string());
        }
        // 200 (GET or HEAD) carries the full length; 304 carries none.
        None if status != StatusCode::NOT_MODIFIED => {
            b = b.header(header::CONTENT_LENGTH, meta.size.to_string());
        }
        None => {}
    }
    b.body(body.unwrap_or_else(Body::empty))
        .unwrap_or_else(|_| s3_error(ObjectError::Io(std::io::Error::other("response build"))))
}

fn range_not_satisfiable(total: u64) -> Response {
    Response::builder()
        .status(StatusCode::RANGE_NOT_SATISFIABLE)
        .header(header::CONTENT_RANGE, format!("bytes */{total}"))
        .header(header::ACCEPT_RANGES, "bytes")
        .body(Body::empty())
        .unwrap_or_else(|_| StatusCode::RANGE_NOT_SATISFIABLE.into_response())
}

enum RangeOutcome {
    Full,
    Partial { start: u64, end: u64 },
    Unsatisfiable,
}

/// Parse a single `Range: bytes=…`. Per RFC 9110 a malformed / unknown-unit / multi-
/// range spec is IGNORED (serve the full 200), while a well-formed but out-of-bounds
/// range is `Unsatisfiable` (→ 416). Byte offsets are inclusive.
fn parse_range(h: Option<&HeaderValue>, total: u64) -> RangeOutcome {
    let Some(spec) = h.and_then(|v| v.to_str().ok()) else {
        return RangeOutcome::Full;
    };
    let Some(rest) = spec.trim().strip_prefix("bytes=") else {
        return RangeOutcome::Full;
    };
    // Single range only — a comma (multi-range) falls back to the full object (S3 does).
    if rest.contains(',') {
        return RangeOutcome::Full;
    }
    let Some((a, b)) = rest.split_once('-') else {
        return RangeOutcome::Full;
    };
    let (a, b) = (a.trim(), b.trim());
    let (start, end) = match (a.is_empty(), b.is_empty()) {
        // "-N": the final N bytes.
        (true, false) => match b.parse::<u64>() {
            Ok(0) => return RangeOutcome::Unsatisfiable,
            Ok(_) if total == 0 => return RangeOutcome::Unsatisfiable,
            Ok(n) => (total - n.min(total), total - 1),
            Err(_) => return RangeOutcome::Full,
        },
        // "start-": from `start` to EOF.
        (false, true) => match a.parse::<u64>() {
            Ok(start) if start < total => (start, total - 1),
            Ok(_) => return RangeOutcome::Unsatisfiable,
            Err(_) => return RangeOutcome::Full,
        },
        // "start-end".
        (false, false) => match (a.parse::<u64>(), b.parse::<u64>()) {
            (Ok(start), Ok(end)) => {
                if start > end || start >= total {
                    return RangeOutcome::Unsatisfiable;
                }
                (start, end.min(total - 1))
            }
            _ => return RangeOutcome::Full,
        },
        // "-" alone: malformed.
        (true, true) => return RangeOutcome::Full,
    };
    RangeOutcome::Partial { start, end }
}

/// RFC 9110 conditional GET: `If-None-Match` (weak compare) takes precedence over
/// `If-Modified-Since`. `true` ⇒ respond 304 Not Modified.
fn not_modified(meta: &ObjectMeta, headers: &HeaderMap) -> bool {
    if let Some(inm) = header_str(headers, header::IF_NONE_MATCH) {
        return if_none_match(&inm, &meta.etag);
    }
    if let Some(ims) = header_str(headers, header::IF_MODIFIED_SINCE)
        && let Some(since) = parse_http_date(&ims)
    {
        return meta.last_modified <= since;
    }
    false
}

/// `If-None-Match`: `*` matches any existing object; otherwise a listed etag equal to
/// ours (weak comparison — a `W/` prefix is ignored) is a match.
fn if_none_match(header_val: &str, etag: &str) -> bool {
    let ours = etag.trim_matches('"');
    header_val.split(',').any(|t| {
        let t = t.trim();
        t == "*" || t.strip_prefix("W/").unwrap_or(t).trim_matches('"') == ours
    })
}

/// Parse an RFC 1123 HTTP-date (`Sun, 06 Nov 1994 08:49:37 GMT`) — the form we emit
/// as Last-Modified and clients echo back. Unparseable ⇒ `None` (⇒ not a 304).
fn parse_http_date(s: &str) -> Option<u64> {
    chrono::NaiveDateTime::parse_from_str(s.trim(), "%a, %d %b %Y %H:%M:%S GMT")
        .ok()
        .map(|dt| dt.and_utc().timestamp().max(0) as u64)
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
        ObjectError::ContentSha256Mismatch => {
            (StatusCode::BAD_REQUEST, "XAmzContentSHA256Mismatch")
        }
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
        let dir = std::env::temp_dir().join(format!(
            "jkb-objhttp-{}",
            TMP.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        (Arc::new(ObjectStore::open(&dir).unwrap()), dir)
    }

    async fn body_str(resp: Response) -> (StatusCode, HeaderMap, String) {
        let status = resp.status();
        let headers = resp.headers().clone();
        let bytes = to_bytes(resp.into_body(), usize::MAX).await.unwrap();
        (
            status,
            headers,
            String::from_utf8_lossy(&bytes).into_owned(),
        )
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
        let etag = r
            .headers()
            .get("etag")
            .unwrap()
            .to_str()
            .unwrap()
            .to_string();
        assert_eq!(etag, format!("\"{:x}\"", Md5::digest(b"hello http")));

        // GET it back.
        let r = app
            .clone()
            .oneshot(
                Request::get("/my-bucket/dir/obj.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
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
            .oneshot(
                Request::delete("/my-bucket/dir/obj.txt")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(r.status(), StatusCode::NO_CONTENT);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn parse_range_cases() {
        let m = |o: RangeOutcome| match o {
            RangeOutcome::Full => "full".to_string(),
            RangeOutcome::Unsatisfiable => "416".to_string(),
            RangeOutcome::Partial { start, end } => format!("{start}-{end}"),
        };
        let r = |s: &str, total: u64| m(parse_range(Some(&HeaderValue::from_str(s).unwrap()), total));
        assert_eq!(r("bytes=0-1023", 10000), "0-1023");
        assert_eq!(r("bytes=1024-", 10000), "1024-9999");
        assert_eq!(r("bytes=-500", 10000), "9500-9999");
        assert_eq!(r("bytes=0-0", 10000), "0-0");
        assert_eq!(r("bytes=9999-100000", 10000), "9999-9999"); // end clamped to EOF
        assert_eq!(r("bytes=-100000", 10000), "0-9999"); // suffix larger than object
        assert_eq!(r("bytes=10000-", 10000), "416"); // start == size
        assert_eq!(r("bytes=10-5", 10000), "416"); // start > end
        assert_eq!(r("bytes=-0", 10000), "416"); // last 0 bytes
        assert_eq!(r("bytes=0-1023", 0), "416"); // empty object
        assert_eq!(r("bytes=0-1,2-3", 10000), "full"); // multi-range → whole object
        assert_eq!(r("items=0-1", 10000), "full"); // unknown unit → ignore
        assert_eq!(r("bytes=abc", 10000), "full"); // malformed → ignore
        assert_eq!(m(parse_range(None, 10000)), "full");
    }

    #[test]
    fn if_none_match_and_http_date_helpers() {
        assert!(if_none_match("*", "abc"));
        assert!(if_none_match("\"abc\"", "abc"));
        assert!(if_none_match("W/\"abc\"", "abc"));
        assert!(if_none_match("\"x\", \"abc\"", "abc"));
        assert!(!if_none_match("\"other\"", "abc"));
        assert_eq!(parse_http_date(&http_date(1_000_000_000)), Some(1_000_000_000));
        assert_eq!(parse_http_date("garbage"), None);
    }

    #[tokio::test]
    async fn range_conditional_and_cache_control_over_http() {
        let (s, dir) = store();
        let app = router(s);
        app.clone()
            .oneshot(Request::put("/rng").body(Body::empty()).unwrap())
            .await
            .unwrap();
        let body = "0123456789";
        let put = app
            .clone()
            .oneshot(
                Request::put("/rng/obj")
                    .header("content-type", "text/plain")
                    .header("cache-control", "public, max-age=3600")
                    .body(Body::from(body))
                    .unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(put.status(), StatusCode::OK);
        let etag = put.headers().get("etag").unwrap().to_str().unwrap().to_string();

        // Full GET: 200 + Accept-Ranges + Cache-Control echoed.
        let (st, h, text) = body_str(
            app.clone()
                .oneshot(Request::get("/rng/obj").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h.get("accept-ranges").unwrap(), "bytes");
        assert_eq!(h.get("cache-control").unwrap(), "public, max-age=3600");
        assert_eq!(text, body);

        // Ranged GET: 206 + Content-Range + partial body.
        let (st, h, text) = body_str(
            app.clone()
                .oneshot(
                    Request::get("/rng/obj")
                        .header("range", "bytes=2-5")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT);
        assert_eq!(h.get("content-range").unwrap(), "bytes 2-5/10");
        assert_eq!(h.get("content-length").unwrap(), "4");
        assert_eq!(text, "2345");

        // Suffix range.
        let (st, _, text) = body_str(
            app.clone()
                .oneshot(
                    Request::get("/rng/obj")
                        .header("range", "bytes=-3")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::PARTIAL_CONTENT);
        assert_eq!(text, "789");

        // Unsatisfiable range: 416 + Content-Range bytes */10.
        let (st, h, _) = body_str(
            app.clone()
                .oneshot(
                    Request::get("/rng/obj")
                        .header("range", "bytes=100-200")
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::RANGE_NOT_SATISFIABLE);
        assert_eq!(h.get("content-range").unwrap(), "bytes */10");

        // Conditional: If-None-Match with the etag → 304, no body/length, keeps validator.
        let (st, h, text) = body_str(
            app.clone()
                .oneshot(
                    Request::get("/rng/obj")
                        .header("if-none-match", &etag)
                        .body(Body::empty())
                        .unwrap(),
                )
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::NOT_MODIFIED);
        assert!(text.is_empty());
        assert_eq!(h.get("etag").unwrap().to_str().unwrap(), etag);
        // A 304 must not advertise the object's full length (an empty-body CL:0 that
        // the framework adds is fine — it's the no-body length, not the resource size).
        assert_ne!(
            h.get("content-length").map(|v| v.to_str().unwrap()),
            Some("10")
        );

        // HEAD: 200 + Accept-Ranges + full Content-Length, no body.
        let (st, h, text) = body_str(
            app.clone()
                .oneshot(Request::head("/rng/obj").body(Body::empty()).unwrap())
                .await
                .unwrap(),
        )
        .await;
        assert_eq!(st, StatusCode::OK);
        assert_eq!(h.get("accept-ranges").unwrap(), "bytes");
        assert_eq!(h.get("content-length").unwrap(), "10");
        assert!(text.is_empty());

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_objects_returns_s3_xml() {
        let (s, dir) = store();
        let app = router(s);
        app.clone()
            .oneshot(Request::put("/b-ucket").body(Body::empty()).unwrap())
            .await
            .unwrap();
        for k in ["img/a", "img/b", "doc/c"] {
            app.clone()
                .oneshot(
                    Request::put(format!("/b-ucket/{k}"))
                        .body(Body::from("x"))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        let r = app
            .clone()
            .oneshot(
                Request::get("/b-ucket?prefix=img/")
                    .body(Body::empty())
                    .unwrap(),
            )
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
        app.clone()
            .oneshot(Request::put("/pg-bucket").body(Body::empty()).unwrap())
            .await
            .unwrap();
        for k in ["a", "b", "c", "d", "e"] {
            app.clone()
                .oneshot(
                    Request::put(format!("/pg-bucket/{k}"))
                        .body(Body::from("x"))
                        .unwrap(),
                )
                .await
                .unwrap();
        }
        // First page of 2.
        let r = app
            .clone()
            .oneshot(
                Request::get("/pg-bucket?max-keys=2")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        let (status, _, xml) = body_str(r).await;
        assert_eq!(status, StatusCode::OK);
        assert!(xml.contains("<IsTruncated>true</IsTruncated>"));
        assert!(xml.contains("<NextContinuationToken>"));
        // Extract token.
        let tok_start =
            xml.find("<NextContinuationToken>").unwrap() + "<NextContinuationToken>".len();
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
        app.clone()
            .oneshot(Request::put("/mp-bucket").body(Body::empty()).unwrap())
            .await
            .unwrap();

        // Initiate.
        let r = app
            .clone()
            .oneshot(
                Request::post("/mp-bucket/big.bin?uploads")
                    .body(Body::empty())
                    .unwrap(),
            )
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
            .oneshot(
                Request::get("/mp-bucket?uploads")
                    .body(Body::empty())
                    .unwrap(),
            )
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
            .oneshot(
                Request::get("/mp-bucket/big.bin")
                    .body(Body::empty())
                    .unwrap(),
            )
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
        app.clone()
            .oneshot(Request::put("/sha-bucket").body(Body::empty()).unwrap())
            .await
            .unwrap();

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
