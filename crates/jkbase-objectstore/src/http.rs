//! S3-compatible HTTP surface over [`ObjectStore`]. Path-style routing
//! (`/{bucket}/{key}`), streamed object bodies (never buffered), and S3-style XML
//! for listings + errors.
//!
//! This layer is **unauthenticated** on its own — tenant auth (SigV4) + bucket
//! ownership is a separate card and is expected to wrap this router as middleware.
//! Multipart upload + presigned URLs are the next slice of this card.

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
            put(put_object)
                .get(get_object)
                .head(head_object)
                .delete(delete_object),
        )
        .with_state(store)
}

// ---- objects --------------------------------------------------------------

async fn put_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Response {
    let content_type = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/octet-stream")
        .to_string();
    // Stream the request body straight to disk — never buffer the whole object.
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

async fn delete_object(
    State(store): State<Arc<ObjectStore>>,
    Path((bucket, key)): Path<(String, String)>,
) -> Response {
    match store.delete_object(&bucket, &key).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(e) => s3_error(e),
    }
}

// ---- buckets --------------------------------------------------------------

async fn create_bucket(State(store): State<Arc<ObjectStore>>, Path(bucket): Path<String>) -> Response {
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
}
