//! Live integration test for [`S3CompatBlobStore`] against an S3-compatible
//! endpoint (MinIO in CI/dev). Marked `#[ignore]` so the default `cargo test` run
//! never reaches the network; run it explicitly against a running MinIO:
//!
//! ```text
//! docker run -d --name jkb-minio -p 9000:9000 \
//!     -e MINIO_ROOT_USER=minioadmin -e MINIO_ROOT_PASSWORD=minioadmin \
//!     minio/minio server /data
//! # create the bucket (one-shot mc), then:
//! cargo test -p jkbase-substrate --features s3 --test s3_minio -- --ignored
//! ```
//!
//! Connection comes from env (with MinIO dev defaults):
//! `JKB_S3_ENDPOINT` (http://127.0.0.1:9000), `JKB_S3_BUCKET` (jkb-cluster),
//! `JKB_S3_KEY` (minioadmin), `JKB_S3_SECRET` (minioadmin).
#![cfg(feature = "s3")]

use jkbase_substrate::{BlobStore, S3CompatBlobStore, S3Config, SubstrateError};
use std::path::Path;

fn env(key: &str, default: &str) -> String {
    std::env::var(key).unwrap_or_else(|_| default.to_string())
}

fn store() -> S3CompatBlobStore {
    S3CompatBlobStore::connect(S3Config {
        endpoint: env("JKB_S3_ENDPOINT", "http://127.0.0.1:9000"),
        region: env("JKB_S3_REGION", "us-east-1"),
        bucket: env("JKB_S3_BUCKET", "jkb-cluster"),
        access_key_id: env("JKB_S3_KEY", "minioadmin"),
        secret_access_key: env("JKB_S3_SECRET", "minioadmin"),
        path_style: true,
        allow_http: true,
        tenant_object_store_host: None,
    })
    .expect("connect")
}

async fn write_tmp(name: &str, bytes: &[u8]) -> std::path::PathBuf {
    let p = std::env::temp_dir().join(format!("jkb-s3-it-{}-{name}", std::process::id()));
    tokio::fs::write(&p, bytes).await.unwrap();
    p
}

/// Exercises the whole BlobStore contract against live MinIO in one ordered test
/// (kept single so the objects it creates don't race across parallel tests).
#[tokio::test]
#[ignore = "requires a running MinIO; run with --ignored"]
async fn s3_blob_contract_round_trips_against_minio() {
    let bs = store();
    let pid = std::process::id();
    let key = format!("snapshots/{pid}/vm.bin");

    // put_file then get_to_file round-trips a multi-chunk body unchanged.
    let payload = vec![0xABu8; 5 * 1024 * 1024 + 7]; // > BufWriter capacity -> multipart path
    let src = write_tmp("src.bin", &payload).await;
    bs.put_file(&key, &src).await.expect("put_file");

    let dst = std::env::temp_dir().join(format!("jkb-s3-it-{pid}-out.bin"));
    bs.get_to_file(&key, &dst).await.expect("get_to_file");
    assert_eq!(tokio::fs::read(&dst).await.unwrap(), payload, "round-trip bytes");

    // head reports the size + an etag; a missing key heads to None.
    let meta = bs.head(&key).await.expect("head").expect("present");
    assert_eq!(meta.size, payload.len() as u64);
    assert!(meta.etag.is_some(), "S3 returns an ETag");
    assert!(bs.head("snapshots/does-not-exist").await.unwrap().is_none());

    // put_if_absent_file: first writes, second is a no-op leaving content intact.
    let dkey = format!("layers/{pid}/dedup");
    let first = write_tmp("first", b"first-content").await;
    let second = write_tmp("second", b"SECOND-content").await;
    assert!(bs.put_if_absent_file(&dkey, &first).await.unwrap(), "first write");
    assert!(!bs.put_if_absent_file(&dkey, &second).await.unwrap(), "already present");
    let dout = std::env::temp_dir().join(format!("jkb-s3-it-{pid}-dedup.out"));
    bs.get_to_file(&dkey, &dout).await.unwrap();
    assert_eq!(tokio::fs::read(&dout).await.unwrap(), b"first-content", "unchanged");

    // list honors the raw-prefix semantics of the trait.
    let listed = bs.list(&format!("layers/{pid}/")).await.unwrap();
    assert!(listed.contains(&dkey), "listed {listed:?}");
    assert!(
        !listed.iter().any(|k| k.starts_with("snapshots/")),
        "prefix excludes other trees"
    );

    // get on a missing key is a typed NotFound, not a generic backend error.
    let miss = bs.get_to_file("nope/missing", Path::new("/tmp/never")).await;
    assert!(matches!(miss, Err(SubstrateError::NotFound(_))), "got {miss:?}");
}
