//! [`S3CompatBlobStore`] — the cluster-grade [`BlobStore`] (R4) over **any**
//! S3-compatible endpoint (AWS S3, MinIO, Ceph RGW, …) via the `object_store`
//! crate. It is exactly ONE blob backend, never privileged and never on the
//! data-disk path; [`connect`](S3CompatBlobStore::connect) refuses an endpoint
//! that resolves to jkbase's OWN tenant object store (the circular-dependency
//! guard shared with the factory).
//!
//! **Streaming, never buffering.** Uploads go through an `object_store::BufWriter`
//! (a single PUT under ~10 MiB, otherwise a multipart upload) and downloads pull
//! the GET body as a chunk stream straight to a local file — so a multi-GiB
//! snapshot / image / layer never lands wholly in memory, preserving the OOM
//! fixes the local backend was built around.
//!
//! **Honest caps.** object_store 0.13 cannot make a *multipart* (i.e. large,
//! streaming) write conditional, so this backend does **not** advertise
//! [`Caps::ATOMIC_PUT_IF_ABSENT`]: [`put_if_absent_file`] is a best-effort
//! head-then-stream, not a mutual-exclusion primitive. For the content-addressed
//! keys dedup actually uses (key = content hash) a race is benign — both writers
//! stream identical bytes, so the worst case is a redundant upload, never
//! corruption. A backend that needs a *true* atomic create stays on
//! [`LocalFsBlobStore`](crate::LocalFsBlobStore) (hard-link), and the factory's
//! capability negotiation sees the difference rather than being lied to.

use crate::{Backend, BlobMeta, BlobStore, Caps, Result, SubstrateError, assert_not_self_referential};
use async_trait::async_trait;
use futures_util::StreamExt;
use object_store::aws::AmazonS3Builder;
use object_store::buffered::BufWriter;
use object_store::path::Path as ObjPath;
use object_store::{GetOptions, ObjectStore, ObjectStoreExt};
use std::path::Path;
use std::sync::Arc;
use tokio::io::AsyncWriteExt;

/// Connection settings for an S3-compatible endpoint.
pub struct S3Config {
    /// Base endpoint, e.g. `https://s3.us-east-1.amazonaws.com` or `http://127.0.0.1:9000`.
    pub endpoint: String,
    /// Region label. Real AWS uses it for signing; MinIO/Ceph accept any non-empty value.
    pub region: String,
    /// Bucket holding the cluster's blobs (NOT a tenant bucket).
    pub bucket: String,
    pub access_key_id: String,
    pub secret_access_key: String,
    /// Path-style addressing (`true` for MinIO / Ceph RGW; `false` selects AWS
    /// virtual-hosted-style `bucket.host`).
    pub path_style: bool,
    /// Permit plaintext `http://` (MinIO in dev). Production AWS is always `https`.
    pub allow_http: bool,
    /// jkbase's OWN tenant object-store host. Cluster state must never resolve to
    /// it (circular dependency); `connect` rejects such an endpoint. `None` skips
    /// the check.
    pub tenant_object_store_host: Option<String>,
}

/// A [`BlobStore`] backed by an S3-compatible object store.
pub struct S3CompatBlobStore {
    store: Arc<dyn ObjectStore>,
}

impl S3CompatBlobStore {
    /// Build a client for `cfg`, refusing a self-referential (tenant-object-store)
    /// endpoint before any network use.
    pub fn connect(cfg: S3Config) -> Result<Self> {
        assert_not_self_referential(&cfg.endpoint, cfg.tenant_object_store_host.as_deref())?;
        let store = AmazonS3Builder::new()
            .with_endpoint(&cfg.endpoint)
            .with_region(&cfg.region)
            .with_bucket_name(&cfg.bucket)
            .with_access_key_id(&cfg.access_key_id)
            .with_secret_access_key(&cfg.secret_access_key)
            .with_virtual_hosted_style_request(!cfg.path_style)
            .with_allow_http(cfg.allow_http)
            .build()
            .map_err(|e| SubstrateError::Backend(format!("s3 builder: {e}")))?;
        Ok(Self { store: Arc::new(store) })
    }

    /// Construct directly from a prepared [`ObjectStore`] (used by tests).
    pub fn from_store(store: Arc<dyn ObjectStore>) -> Self {
        Self { store }
    }
}

/// Parse a blob key into an object-store path, rejecting an empty key.
fn obj_path(key: &str) -> Result<ObjPath> {
    if key.is_empty() {
        return Err(SubstrateError::Backend("empty blob key".into()));
    }
    ObjPath::parse(key).map_err(|e| SubstrateError::Backend(format!("invalid blob key {key:?}: {e}")))
}

/// Map object_store errors onto the substrate seam, preserving "not found".
fn map_err(e: object_store::Error) -> SubstrateError {
    match e {
        object_store::Error::NotFound { path, .. } => SubstrateError::NotFound(path),
        other => SubstrateError::Backend(other.to_string()),
    }
}

#[async_trait]
impl BlobStore for S3CompatBlobStore {
    async fn put_file(&self, key: &str, src: &Path) -> Result<()> {
        let path = obj_path(key)?;
        let mut reader = tokio::fs::File::open(src).await?;
        let mut writer = BufWriter::new(self.store.clone(), path);
        if let Err(e) = tokio::io::copy(&mut reader, &mut writer).await {
            let _ = writer.abort().await;
            return Err(e.into());
        }
        // shutdown() finalizes the single PUT or completes the multipart upload —
        // the object appears atomically only on success.
        writer.shutdown().await?;
        Ok(())
    }

    async fn put_if_absent_file(&self, key: &str, src: &Path) -> Result<bool> {
        // Best-effort (see module docs): not atomic, but safe for content-addressed
        // keys. This backend does not advertise ATOMIC_PUT_IF_ABSENT.
        if self.head(key).await?.is_some() {
            return Ok(false);
        }
        self.put_file(key, src).await?;
        Ok(true)
    }

    async fn get_to_file(&self, key: &str, dst: &Path) -> Result<()> {
        let path = obj_path(key)?;
        // get_opts is the dyn-safe accessor (the convenience `get` is Sized-only).
        let res = self
            .store
            .get_opts(&path, GetOptions::default())
            .await
            .map_err(map_err)?;
        if let Some(parent) = dst.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        let mut file = tokio::fs::File::create(dst).await?;
        let mut stream = res.into_stream();
        while let Some(chunk) = stream.next().await {
            let bytes = chunk.map_err(map_err)?;
            file.write_all(&bytes).await?;
        }
        file.sync_all().await?;
        Ok(())
    }

    async fn head(&self, key: &str) -> Result<Option<BlobMeta>> {
        let path = obj_path(key)?;
        // A HEAD via get_opts: fetch metadata without the body (dyn-safe).
        let opts = GetOptions { head: true, ..Default::default() };
        match self.store.get_opts(&path, opts).await {
            Ok(res) => Ok(Some(BlobMeta {
                key: key.to_string(),
                size: res.meta.size,
                etag: res.meta.e_tag,
            })),
            Err(object_store::Error::NotFound { .. }) => Ok(None),
            Err(e) => Err(map_err(e)),
        }
    }

    async fn list(&self, prefix: &str) -> Result<Vec<String>> {
        // Narrow the server-side scan to the prefix's "directory" segment, then
        // honor the trait's raw `starts_with` semantics (matching LocalFsBlobStore)
        // by filtering the returned keys — so e.g. prefix "lay" still matches
        // "layers/x" even though object_store prefixes are segment-aligned.
        let dir = prefix.rsplit_once('/').map(|(d, _)| d).unwrap_or("");
        let listpfx = match dir.is_empty() {
            true => None,
            false => Some(obj_path(dir)?),
        };
        let mut out = Vec::new();
        let mut stream = self.store.list(listpfx.as_ref());
        while let Some(meta) = stream.next().await {
            let key = meta.map_err(map_err)?.location.to_string();
            if key.starts_with(prefix) {
                out.push(key);
            }
        }
        out.sort();
        Ok(out)
    }

    async fn delete(&self, key: &str) -> Result<()> {
        let path = obj_path(key)?;
        match self.store.delete(&path).await {
            Ok(()) => Ok(()),
            // Idempotent: absent is success (matches LocalFsBlobStore semantics).
            Err(object_store::Error::NotFound { .. }) => Ok(()),
            Err(e) => Err(map_err(e)),
        }
    }
}

impl Backend for S3CompatBlobStore {
    fn backend_name(&self) -> &str {
        "s3"
    }
    fn caps(&self) -> Caps {
        // Deliberately empty: streaming (multipart) put_if_absent cannot be made
        // atomic on object_store 0.13, so we do NOT claim ATOMIC_PUT_IF_ABSENT.
        Caps::empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connect_rejects_self_referential_endpoint() {
        // Pointing the cluster's blob store at jkbase's own tenant S3 is circular.
        // (S3CompatBlobStore is not Debug, so assert on the Result directly.)
        let res = S3CompatBlobStore::connect(S3Config {
            endpoint: "https://s3.jkbase.app".into(),
            region: "us-east-1".into(),
            bucket: "cluster-state".into(),
            access_key_id: "k".into(),
            secret_access_key: "s".into(),
            path_style: true,
            allow_http: false,
            tenant_object_store_host: Some("s3.jkbase.app".into()),
        });
        assert!(matches!(res, Err(SubstrateError::Backend(_))));
    }

    #[test]
    fn connect_accepts_external_endpoint_and_reports_honest_caps() {
        let bs = S3CompatBlobStore::connect(S3Config {
            endpoint: "http://127.0.0.1:9000".into(),
            region: "us-east-1".into(),
            bucket: "cluster-state".into(),
            access_key_id: "minioadmin".into(),
            secret_access_key: "minioadmin".into(),
            path_style: true,
            allow_http: true,
            tenant_object_store_host: Some("s3.jkbase.app".into()),
        })
        .unwrap();
        assert_eq!(bs.backend_name(), "s3");
        // Honest: streaming put_if_absent is best-effort, so no atomic claim.
        assert!(!bs.caps().contains(Caps::ATOMIC_PUT_IF_ABSENT));
    }

    #[test]
    fn empty_key_is_rejected() {
        assert!(matches!(obj_path(""), Err(SubstrateError::Backend(_))));
    }
}
