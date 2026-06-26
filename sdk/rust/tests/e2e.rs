//! Live end-to-end: drive the public client against the real engine router over real
//! HTTP. Hermetic — an in-process axum server on an ephemeral loopback port, no external
//! services — so it runs in CI (mirrors the engine's own `e2e_over_real_http`). The bare
//! `router` is unauthenticated (per-project FS root is the real boundary), so this proves
//! the wire protocol + XML parsing end to end; SigV4 signing correctness is pinned
//! separately by the `presign_matches_the_shared_cross_vector` unit test.

use bytes::Bytes;
use futures_util::{StreamExt, TryStreamExt};
use jkbase_objectstore::{ObjectStore, router};
use jkbase_objectstore_client::{Error, ListObjectsOptions, ObjectClient};
use md5::{Digest, Md5};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// Spin up a fresh in-process store + server, return a client pointed at it.
async fn spawn() -> (ObjectClient, std::path::PathBuf) {
    let dir = std::env::temp_dir().join(format!(
        "jkb-objclient-e2e-{}-{}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    ));
    let _ = std::fs::remove_dir_all(&dir);
    let store = Arc::new(ObjectStore::open(&dir).unwrap());
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        let _ = axum::serve(listener, router(store)).await;
    });
    let client = ObjectClient::new(format!("http://{addr}"), "AK", "SK");
    (client, dir)
}

#[tokio::test]
async fn object_lifecycle_buffered_and_streamed() {
    let (c, dir) = spawn().await;
    c.create_bucket("bkt").await.unwrap();

    // Buffered put -> get -> head.
    let want_etag = md5_hex(b"hello sdk");
    let etag = c
        .put_object("bkt", "dir/a.txt", b"hello sdk".to_vec(), "text/plain")
        .await
        .unwrap();
    assert_eq!(etag, want_etag);
    assert_eq!(
        &c.get_object_bytes("bkt", "dir/a.txt").await.unwrap()[..],
        b"hello sdk"
    );
    let meta = c.head_object("bkt", "dir/a.txt").await.unwrap();
    assert_eq!(meta.content_length, Some(9));
    assert_eq!(meta.content_type.as_deref(), Some("text/plain"));
    assert_eq!(meta.etag.as_deref(), Some(want_etag.as_str()));

    // Streamed put (wrap_stream) -> streamed get (into_stream).
    let parts = futures_util::stream::iter(vec![
        Ok::<_, std::io::Error>(Bytes::from_static(b"AAAA")),
        Ok(Bytes::from_static(b"BB")),
    ]);
    c.put_object_stream(
        "bkt",
        "big",
        reqwest::Body::wrap_stream(parts),
        6,
        "application/octet-stream",
    )
    .await
    .unwrap();
    let got = c.get_object("bkt", "big").await.unwrap();
    let collected: Vec<Bytes> = got.into_stream().try_collect().await.unwrap();
    let joined: Vec<u8> = collected.into_iter().flatten().collect();
    assert_eq!(joined, b"AAAABB");

    // Delete -> 404 -> typed not-found.
    c.delete_object("bkt", "dir/a.txt").await.unwrap();
    let err = c.get_object("bkt", "dir/a.txt").await.unwrap_err();
    assert!(err.is_not_found(), "{err:?}");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn listing_pagination_and_delimiter() {
    let (c, dir) = spawn().await;
    c.create_bucket("lst").await.unwrap();
    for k in ["a", "b", "c", "d", "e"] {
        c.put_object("lst", k, b"x".to_vec(), "text/plain")
            .await
            .unwrap();
    }

    // Page 1 of 2 -> truncated + token.
    let p1 = c
        .list_objects("lst", &ListObjectsOptions::new().max_keys(2))
        .await
        .unwrap();
    assert_eq!(p1.objects.len(), 2);
    assert!(p1.is_truncated);
    assert_eq!(p1.max_keys, 2);
    let token = p1.next_continuation_token.clone().expect("token");

    // Page 2 via continuation token.
    let p2 = c
        .list_objects(
            "lst",
            &ListObjectsOptions::new()
                .max_keys(2)
                .continuation_token(token),
        )
        .await
        .unwrap();
    assert_eq!(
        p2.objects
            .iter()
            .map(|o| o.key.as_str())
            .collect::<Vec<_>>(),
        vec!["c", "d"]
    );

    // Eager auto-page collects all five.
    let mut all = c.list_all_keys("lst", "").await.unwrap();
    all.sort();
    assert_eq!(all, vec!["a", "b", "c", "d", "e"]);

    // Lazy auto-paging stream collects all five too (page size 2 -> 3 pages).
    let mut keys = Vec::new();
    let mut pages = Box::pin(c.list_objects_paged("lst", ListObjectsOptions::new().max_keys(2)));
    while let Some(page) = pages.next().await {
        for o in page.unwrap().objects {
            keys.push(o.key);
        }
    }
    keys.sort();
    assert_eq!(keys, vec!["a", "b", "c", "d", "e"]);

    // Delimiter folding: a/x a/y fold to common prefix "a/"; top-level "b" stays an object.
    c.create_bucket("fold").await.unwrap();
    c.put_object("fold", "a/x", b"1".to_vec(), "text/plain")
        .await
        .unwrap();
    c.put_object("fold", "a/y", b"1".to_vec(), "text/plain")
        .await
        .unwrap();
    c.put_object("fold", "b", b"1".to_vec(), "text/plain")
        .await
        .unwrap();
    let page = c
        .list_objects("fold", &ListObjectsOptions::new().delimiter("/"))
        .await
        .unwrap();
    assert_eq!(page.common_prefixes, vec!["a/".to_string()]);
    assert_eq!(
        page.objects
            .iter()
            .map(|o| o.key.as_str())
            .collect::<Vec<_>>(),
        vec!["b"]
    );

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn multipart_roundtrip_and_abort() {
    let (c, dir) = spawn().await;
    c.create_bucket("multi").await.unwrap();

    let mut up = c
        .create_multipart("multi", "big.bin", "application/octet-stream")
        .await
        .unwrap();
    assert!(!up.upload_id().is_empty());
    up.upload_part(1, b"AAAA".to_vec()).await.unwrap();
    up.upload_part(2, b"BB".to_vec()).await.unwrap();

    let pending = c.list_multipart_uploads("multi").await.unwrap();
    assert!(pending.iter().any(|u| u.key == "big.bin"), "{pending:?}");

    up.complete().await.unwrap();
    assert_eq!(
        &c.get_object_bytes("multi", "big.bin").await.unwrap()[..],
        b"AAAABB"
    );

    // Abort discards a started upload.
    let up2 = c
        .create_multipart("multi", "scratch", "application/octet-stream")
        .await
        .unwrap();
    up2.abort().await.unwrap();

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn typed_errors_and_buckets() {
    let (c, dir) = spawn().await;
    c.create_bucket("errs").await.unwrap();

    // Re-create -> BucketAlreadyExists.
    let err = c.create_bucket("errs").await.unwrap_err();
    assert_eq!(
        err.code(),
        Some(&jkbase_objectstore_client::S3ErrorCode::BucketAlreadyExists),
        "{err:?}"
    );

    // List a missing bucket -> NoSuchBucket.
    let err = c
        .list_objects("missingbk", &ListObjectsOptions::new())
        .await
        .unwrap_err();
    assert_eq!(
        err.code(),
        Some(&jkbase_objectstore_client::S3ErrorCode::NoSuchBucket),
        "{err:?}"
    );

    // bucket_exists maps 404 -> Ok(false).
    assert!(c.bucket_exists("errs").await.unwrap());
    assert!(!c.bucket_exists("ghostbk").await.unwrap());

    // list_buckets sees what we created.
    c.create_bucket("errt").await.unwrap();
    let mut names = c.list_buckets().await.unwrap();
    names.sort();
    assert_eq!(names, vec!["errs", "errt"]);

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn presigned_urls_are_usable() {
    let (c, dir) = spawn().await;
    c.create_bucket("presign").await.unwrap();

    // presigned PUT: a plain HTTP client uploads to the minted URL.
    let put_url = c.presigned_put("presign", "k.txt", 900).unwrap();
    let http = reqwest::Client::new();
    let r = http
        .put(&put_url)
        .body("presigned body")
        .send()
        .await
        .unwrap();
    assert!(r.status().is_success(), "PUT {} -> {}", put_url, r.status());

    // presigned GET: fetch it back with no auth header.
    let get_url = c.presigned_get("presign", "k.txt", 900).unwrap();
    let body = reqwest::get(&get_url).await.unwrap().text().await.unwrap();
    assert_eq!(body, "presigned body");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn keys_with_xml_special_chars_round_trip() {
    let (c, dir) = spawn().await;
    c.create_bucket("xkeys").await.unwrap();
    // Keys exercising the wire-encoding (space, &, <, >, unicode) AND the server's
    // xml_escape ↔ client unescape seam on the listing path.
    let keys = ["a&b", "c d", "e<f>g", "u/\u{2713}"];
    for k in keys {
        c.put_object("xkeys", k, b"v".to_vec(), "text/plain")
            .await
            .unwrap();
    }

    // Listing returns every key byte-identical (escaped server-side, unescaped client-side).
    let mut got = c.list_all_keys("xkeys", "").await.unwrap();
    got.sort();
    let mut want: Vec<String> = keys.iter().map(|k| k.to_string()).collect();
    want.sort();
    assert_eq!(got, want);

    // The trickiest keys also GET back over the real wire (space + ampersand encoding).
    assert_eq!(&c.get_object_bytes("xkeys", "c d").await.unwrap()[..], b"v");
    assert_eq!(&c.get_object_bytes("xkeys", "a&b").await.unwrap()[..], b"v");

    let _ = std::fs::remove_dir_all(&dir);
}

#[tokio::test]
async fn dot_segment_keys_are_rejected_client_side() {
    let (c, dir) = spawn().await;
    c.create_bucket("dots").await.unwrap();

    // '.'/'..' segments would be normalized away by HTTP clients → signed≠sent. The client
    // refuses them with a typed InvalidKey BEFORE any request, so nothing is mis-stored.
    for bad in ["a/../c", "a/./c", "..", "x/..", ""] {
        let err = c
            .put_object("dots", bad, b"v".to_vec(), "text/plain")
            .await
            .unwrap_err();
        assert!(matches!(err, Error::InvalidKey(_)), "{bad:?}: {err:?}");
        assert!(c.get_object("dots", bad).await.is_err());
        assert!(c.presigned_get("dots", bad, 900).is_err());
    }

    // A key that merely CONTAINS dots (not as a whole segment) is fine.
    c.put_object("dots", "v1.2.3/file.txt", b"v".to_vec(), "text/plain")
        .await
        .unwrap();
    assert_eq!(
        &c.get_object_bytes("dots", "v1.2.3/file.txt").await.unwrap()[..],
        b"v"
    );

    let _ = std::fs::remove_dir_all(&dir);
}

/// The engine's ETag is the lowercase hex MD5 of the body.
fn md5_hex(b: &[u8]) -> String {
    format!("{:x}", Md5::digest(b))
}
