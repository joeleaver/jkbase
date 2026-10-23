use crate::cors::CorsConfig;
use crate::index::{Index, LAYOUT_V2, ObjectRow, PartRow, SegRef};
use crate::segments::{ByteStream, LocalSegments, SegmentStore, SegmentWriter};
use futures_util::{StreamExt, TryStreamExt};
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock, Mutex, Weak};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt};

static SEQ: AtomicU64 = AtomicU64::new(0);

/// The index file and segment directory under a project's store root. Dot-prefixed: a
/// layout-1 bucket directory can't start with `.`, so neither can collide with one.
const INDEX_FILE: &str = ".index.redb";
const SEGMENTS_DIR: &str = ".segments";

/// Concurrent listings of one store (one project). A listing is an index range scan now,
/// but a delimiter-less scan of a large bucket still reads up to `max_keys` rows; extra
/// requests wait their turn rather than multiply that work. They are not refused.
const MAX_CONCURRENT_LISTS: usize = 4;

/// Per-idle-read timeout for put_object / upload_part (slow-loris guard).
const IDLE_TIMEOUT: Duration = Duration::from_secs(30);

/// Floor on a single upload body's total wall-clock budget. A tiny upload can't
/// camp a connection longer than this (the per-read idle timeout is the finer
/// slow-loris guard); larger uploads get proportionally more (see below).
const MIN_UPLOAD_DEADLINE: Duration = Duration::from_secs(3600);

/// Throughput floor used to size a large upload's total budget: the deadline is
/// `declared_bytes / MIN_UPLOAD_RATE`, floored at `MIN_UPLOAD_DEADLINE`. Set low
/// (1 MiB/s) so a genuinely slow link can still complete a near-quota single PUT,
/// while a connection that delivers nothing is still bounded. (Huge objects should
/// use multipart, but a single large PUT over a slow link is now allowed.)
const MIN_UPLOAD_RATE: u64 = 1024 * 1024;

/// Absolute CEILING on a single upload body's total budget. The size-aware deadline
/// scales with the declared length, which the front-end only bounds by the (possibly
/// very large) byte quota — so without this ceiling a large-quota tenant could
/// declare a huge length and hold a connection open for days/years by trickling one
/// byte per `IDLE_TIMEOUT`. 6h covers a full default-quota (16 GiB) single PUT at the
/// floor rate (~4.6h); larger objects must use multipart. The index's
/// `PENDING_ORPHAN_AGE` must stay above this.
const MAX_UPLOAD_DEADLINE: Duration = Duration::from_secs(6 * 3600);

/// Total wall-clock budget for one upload body of `declared_len` (the declared
/// Content-Length / decoded length), clamped to `[MIN_UPLOAD_DEADLINE,
/// MAX_UPLOAD_DEADLINE]`. `None` (length unknown) uses the floor. Combined with
/// [`IDLE_TIMEOUT`] per read, this bounds both per-read stalls and total connection
/// hold while scaling the budget to the work.
fn upload_deadline(declared_len: Option<u64>) -> Duration {
    match declared_len {
        Some(n) => {
            Duration::from_secs(n / MIN_UPLOAD_RATE).clamp(MIN_UPLOAD_DEADLINE, MAX_UPLOAD_DEADLINE)
        }
        None => MIN_UPLOAD_DEADLINE,
    }
}

/// Errors surfaced by the object store. The HTTP layer maps these onto S3 error
/// codes (NoSuchBucket, NoSuchKey, BucketNotEmpty, …).
#[derive(Debug, thiserror::Error)]
pub enum ObjectError {
    #[error("no such bucket: {0}")]
    NoSuchBucket(String),
    #[error("no such key: {0}")]
    NoSuchKey(String),
    #[error("bucket already exists: {0}")]
    BucketAlreadyExists(String),
    #[error("bucket not empty: {0}")]
    BucketNotEmpty(String),
    #[error("invalid bucket name: {0}")]
    InvalidBucketName(String),
    #[error("invalid key: {0}")]
    InvalidKey(String),
    #[error("corrupt object metadata for {0}")]
    CorruptMeta(String),
    #[error("no such upload: {0}")]
    NoSuchUpload(String),
    #[error("invalid argument: {0}")]
    InvalidArgument(String),
    /// Slow-loris: idle-timeout per read or total upload cap exceeded.
    #[error("request timeout: {0}")]
    Timeout(String),
    /// x-amz-content-sha256 mismatch (body corrupted in transit).
    #[error("content sha256 mismatch")]
    ContentSha256Mismatch,
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Per-upload info persisted at multipart-initiate (the final object's key +
/// content-type, applied at complete).
#[derive(Serialize, Deserialize)]
pub(crate) struct UploadInfo {
    pub key: String,
    pub content_type: String,
    /// Unix seconds at which the upload was initiated. Defaulted to 0 for
    /// uploads created before this field existed (pre-hardening).
    #[serde(default)]
    pub initiated: u64,
    /// `Cache-Control` captured at initiate, applied to the completed object.
    #[serde(default)]
    pub cache_control: Option<String>,
}

type Result<T> = std::result::Result<T, ObjectError>;

/// Metadata for a stored object (mirrors the S3 fields the API exposes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// S3 etag (the API layer quotes it): hex MD5 of the bytes for a single PUT,
    /// `md5(part md5s)-<count>` for a multipart upload.
    pub etag: String,
    pub content_type: String,
    /// Last-modified, unix seconds.
    pub last_modified: u64,
    /// Client-supplied `Cache-Control` to echo on GET/HEAD. `#[serde(default)]` so
    /// rows written before this field existed still deserialize (as `None`).
    #[serde(default)]
    pub cache_control: Option<String>,
}

/// Result page from `list_objects`. Holds the current page plus pagination
/// state for the next call.
#[derive(Debug)]
pub struct ListPage {
    pub objects: Vec<ObjectMeta>,
    pub is_truncated: bool,
    /// When `is_truncated`, the last key returned; pass as `start_after` next call.
    pub next_continuation_token: Option<String>,
}

/// Result page from `list_v2` — like [`ListPage`] but with S3 `delimiter` support.
/// Keys whose remainder after `prefix` contains the delimiter are folded into a
/// single `common_prefixes` entry (the "folder" at this level) instead of being
/// listed individually; only keys with no further delimiter appear in `objects`.
#[derive(Debug)]
pub struct ListV2Page {
    pub objects: Vec<ObjectMeta>,
    /// Distinct `prefix + …segment… + delimiter` strings folded out of `objects`,
    /// sorted; empty when `delimiter` is `None`.
    pub common_prefixes: Vec<String>,
    pub is_truncated: bool,
    /// When `is_truncated`, the last entry's sort key — an object key OR a common
    /// prefix. Pass as `start_after`/continuation-token on the next call.
    pub next_continuation_token: Option<String>,
}

/// A pending multipart upload (returned by `list_multipart_uploads`).
#[derive(Debug)]
pub struct MultipartUpload {
    pub upload_id: String,
    pub key: String,
    /// Unix seconds at which the upload was initiated (0 for pre-hardening uploads).
    pub initiated: u64,
}

/// An object's bytes as of the moment it was looked up: its segment manifest. Streaming
/// opens segments one at a time, and an overwrite or delete after the lookup leaves them
/// readable for the index's `GRACE`, so a GET never mixes two versions.
pub struct ObjectBody {
    segments: Vec<SegRef>,
    store: Arc<dyn SegmentStore>,
}

impl ObjectBody {
    /// Stream bytes `[start, start + len)` of the object. The caller bounds the range by
    /// the object's size (it has already promised the client a Content-Length).
    pub fn stream(self, start: u64, len: u64) -> ByteStream {
        let end = start.saturating_add(len);
        let mut plan = Vec::new();
        let mut pos = 0u64;
        for s in self.segments {
            let (lo, hi) = (start.max(pos), end.min(pos + s.size));
            if lo < hi {
                plan.push((s.id, lo - pos, hi - lo));
            }
            pos += s.size;
        }
        let store = self.store;
        Box::pin(
            futures_util::stream::iter(plan)
                .then(move |(id, offset, n)| {
                    let store = store.clone();
                    async move { store.read(&id, offset, n).await }
                })
                .try_flatten(),
        )
    }

    /// The whole object.
    pub fn into_stream(self) -> ByteStream {
        let total = self.segments.iter().map(|s| s.size).sum();
        self.stream(0, total)
    }
}

/// One open store per root per process: the index file is exclusively locked while open,
/// and two handles on one root would be two views of the truth. Entries are weak, so a
/// store closes once nothing uses it.
static OPEN: LazyLock<Mutex<HashMap<PathBuf, Weak<Shared>>>> = LazyLock::new(Default::default);

struct Shared {
    index: Index,
    segments: Arc<dyn SegmentStore>,
    list_permits: tokio::sync::Semaphore,
    index_path: PathBuf,
    /// `(dev, inode)` of the index file this handle opened — see [`ObjectStore::is_current`].
    ident: (u64, u64),
}

impl Shared {
    fn is_current(&self) -> bool {
        file_ident(&self.index_path).is_ok_and(|id| id == self.ident)
    }
}

/// A tenant object store rooted at `root` (one per project): a transactional index of
/// buckets, objects and uploads, plus the segments that hold the bytes. See
/// `docs/storage-scale-out-design.md`.
pub struct ObjectStore {
    inner: Arc<Shared>,
}

impl ObjectStore {
    /// Open (creating if absent) the object store rooted at `root`, migrating a layout-1
    /// store on first open. Blocking; cheap once a root has been migrated.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        let mut open = OPEN.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(inner) = open.get(&root).and_then(Weak::upgrade)
            && inner.is_current()
        {
            return Ok(Self { inner });
        }
        std::fs::create_dir_all(&root)?;
        let index_path = root.join(INDEX_FILE);
        let index = Index::open(&index_path)?;
        let ident = file_ident(&index_path)?;
        let local = Arc::new(LocalSegments::open(root.join(SEGMENTS_DIR))?);
        if index.layout()? < LAYOUT_V2 {
            crate::legacy::migrate(&root, &index, &local)?;
        }
        let inner = Arc::new(Shared {
            index,
            segments: local,
            list_permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_LISTS),
            index_path,
            ident,
        });
        open.retain(|_, w| w.strong_count() > 0);
        open.insert(root, Arc::downgrade(&inner));
        Ok(Self { inner })
    }

    /// Whether this handle's index is still the one at its root. False once the root was
    /// deleted (and perhaps recreated) under it — e.g. a project deleted and re-registered
    /// with the same id: a cached handle must then be dropped and the store reopened, or
    /// writes would land in the previous incarnation's unlinked index.
    pub fn is_current(&self) -> bool {
        self.inner.is_current()
    }

    /// Run `f` against the index on the blocking pool.
    async fn ix<T: Send + 'static>(
        &self,
        f: impl FnOnce(&Index) -> Result<T> + Send + 'static,
    ) -> Result<T> {
        let inner = self.inner.clone();
        tokio::task::spawn_blocking(move || f(&inner.index))
            .await
            .map_err(|e| ObjectError::Io(std::io::Error::other(e)))?
    }

    // ---- buckets ----------------------------------------------------------

    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.create_bucket(&bucket, now_secs()))
            .await
    }

    /// S3 refuses to delete a bucket that still holds objects or unfinished multipart
    /// uploads. The bucket's CORS config goes with it.
    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.delete_bucket(&bucket)).await
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        self.ix(|ix| ix.list_buckets()).await
    }

    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.bucket_exists(&bucket)).await
    }

    async fn require_bucket(&self, bucket: &str) -> Result<()> {
        if !self.bucket_exists(bucket).await? {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        Ok(())
    }

    // ---- per-bucket CORS config -------------------------------------------

    /// Store the bucket's CORS config (bucket must exist).
    pub async fn put_bucket_cors(&self, bucket: &str, cfg: &CorsConfig) -> Result<()> {
        validate_bucket(bucket)?;
        let (bucket, cfg) = (bucket.to_string(), cfg.clone());
        self.ix(move |ix| ix.set_cors(&bucket, Some(cfg))).await
    }

    /// The bucket's CORS config, or `None` if unset. An unreadable config reads as
    /// `None` (fail-open to "no CORS"): it governs only the tenant's own bucket, so the
    /// worst case is their browser client loses access, never a cross-tenant leak.
    pub async fn get_bucket_cors(&self, bucket: &str) -> Result<Option<CorsConfig>> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.get_cors(&bucket)).await
    }

    /// Remove the bucket's CORS config (idempotent).
    pub async fn delete_bucket_cors(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.set_cors(&bucket, None)).await
    }

    // ---- segments ---------------------------------------------------------

    /// Stream `reader` into a new segment (recorded pending before its first byte).
    /// Returns `(segment id, size, raw md5)`. On any failure the segment is discarded.
    async fn write_segment<R: AsyncRead + Unpin>(
        &self,
        reader: &mut R,
        expected_sha256: Option<&str>,
        declared_len: Option<u64>,
    ) -> Result<(String, u64, Vec<u8>)> {
        let id = new_id();
        let pid = id.clone();
        self.ix(move |ix| ix.add_pending(&pid, now_secs())).await?;
        let written = match self.inner.segments.create(&id).await {
            Ok(w) => write_stream(w, reader, expected_sha256, declared_len).await,
            Err(e) => Err(e.into()),
        };
        match written {
            Ok((size, md5)) => Ok((id, size, md5)),
            Err(e) => {
                self.discard(id).await;
                Err(e)
            }
        }
    }

    /// Release a pending segment the caller won't reference. Best effort: if this fails
    /// the sweeper reclaims it once it is `PENDING_ORPHAN_AGE` old.
    async fn discard(&self, id: String) {
        let _ = self
            .ix(move |ix| ix.discard_pending(&[id], now_secs()))
            .await;
    }

    /// Delete the bytes of every segment that is due — unreachable for at least the
    /// grace period, or pending past the orphan age — then forget them. Returns how many
    /// were reclaimed; one that fails to delete stays listed and is retried next sweep.
    pub async fn collect_garbage(&self) -> Result<usize> {
        let due = self.ix(|ix| ix.due_segments(now_secs())).await?;
        let mut gone = Vec::with_capacity(due.len());
        for id in due {
            if self.inner.segments.delete(&id).await.is_ok() {
                gone.push(id);
            }
        }
        let n = gone.len();
        if n > 0 {
            self.ix(move |ix| ix.forget_segments(&gone)).await?;
        }
        Ok(n)
    }

    // ---- objects ----------------------------------------------------------

    /// Stream `reader` into `bucket/key`, computing the MD5 etag as it goes (the
    /// body is never fully buffered). Overwrites any existing object atomically.
    ///
    /// `expected_sha256`: when `Some(hex)` (64-char lowercase hex), the SHA-256 of
    /// the streamed bytes is verified and `ContentSha256Mismatch` returned on
    /// mismatch. Pass `None` for UNSIGNED-PAYLOAD or STREAMING-* bodies (no check).
    ///
    /// Note: `aws-chunked` (STREAMING-AWS4-HMAC-SHA256-PAYLOAD) bodies are stored
    /// raw / not de-framed; our JS SDK uses UNSIGNED-PAYLOAD plain bodies.
    pub async fn put_object<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        key: &str,
        reader: R,
        content_type: &str,
        expected_sha256: Option<&str>,
    ) -> Result<ObjectMeta> {
        self.put_object_capped(
            bucket,
            key,
            reader,
            content_type,
            None,
            expected_sha256,
            None,
        )
        .await
    }

    /// Like [`put_object`], but `declared_len` (the declared Content-Length) sizes the
    /// total upload deadline — see [`upload_deadline`]. Authenticated front-ends pass
    /// the declared length so a large single PUT over a slow link isn't capped at the
    /// small-upload floor; plain `put_object` (unknown length) uses the floor.
    #[allow(clippy::too_many_arguments)]
    pub async fn put_object_capped<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        key: &str,
        mut reader: R,
        content_type: &str,
        cache_control: Option<&str>,
        expected_sha256: Option<&str>,
        declared_len: Option<u64>,
    ) -> Result<ObjectMeta> {
        validate_key(key)?;
        validate_bucket(bucket)?;
        self.require_bucket(bucket).await?;
        let (id, size, md5) = self
            .write_segment(&mut reader, expected_sha256, declared_len)
            .await?;
        let row = ObjectRow {
            meta: ObjectMeta {
                key: key.to_string(),
                size,
                etag: hex(&md5),
                content_type: content_type.to_string(),
                last_modified: now_secs(),
                cache_control: cache_control.map(str::to_string),
            },
            segments: vec![SegRef {
                id: id.clone(),
                size,
            }],
        };
        let meta = row.meta.clone();
        let bucket = bucket.to_string();
        // The bucket can be deleted while the body streams; then the segment is let go.
        if let Err(e) = self
            .ix(move |ix| ix.commit_object(&bucket, &row, now_secs(), false))
            .await
        {
            self.discard(id).await;
            return Err(e);
        }
        Ok(meta)
    }

    /// Look up `bucket/key`, returning its metadata and a handle that streams its bytes.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<(ObjectMeta, ObjectBody)> {
        let row = self.row(bucket, key).await?;
        Ok((
            row.meta,
            ObjectBody {
                segments: row.segments,
                store: self.inner.segments.clone(),
            },
        ))
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        Ok(self.row(bucket, key).await?.meta)
    }

    async fn row(&self, bucket: &str, key: &str) -> Result<ObjectRow> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let (bucket, key) = (bucket.to_string(), key.to_string());
        self.ix(move |ix| ix.get_object(&bucket, &key)).await
    }

    /// The size of `bucket/key` if it currently exists, else `None` (a missing key or
    /// bucket is not an error). Lets the quota gate reserve only the NET delta of an
    /// overwrite, so re-PUTting an existing key can't false-trip the object/byte cap.
    pub async fn object_size(&self, bucket: &str, key: &str) -> Result<Option<u64>> {
        match self.head_object(bucket, key).await {
            Ok(meta) => Ok(Some(meta.size)),
            Err(ObjectError::NoSuchKey(_)) | Err(ObjectError::NoSuchBucket(_)) => Ok(None),
            Err(e) => Err(e),
        }
    }

    /// Idempotent (S3 DELETE returns success even if the key is absent).
    pub async fn delete_object(&self, bucket: &str, key: &str) -> Result<()> {
        validate_bucket(bucket)?;
        validate_key(key)?;
        let (bucket, key) = (bucket.to_string(), key.to_string());
        self.ix(move |ix| ix.delete_object(&bucket, &key, now_secs()))
            .await
    }

    /// List objects in `bucket` whose key starts with `prefix`, sorted by key.
    ///
    /// Returns a page of up to `max_keys` objects (clamped to 1..=1000).
    /// `start_after`: skip all keys ≤ this value (both V1 marker and V2
    /// continuation-token are passed here by the HTTP layer). A thin delegate over
    /// [`list_v2`] with no delimiter (so `common_prefixes` is always empty).
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListPage> {
        let page = self
            .list_v2(bucket, prefix, None, start_after, max_keys)
            .await?;
        Ok(ListPage {
            objects: page.objects,
            is_truncated: page.is_truncated,
            next_continuation_token: page.next_continuation_token,
        })
    }

    /// List objects in `bucket` under `prefix`, optionally folding by `delimiter`.
    ///
    /// With `delimiter = Some("/")` this gives S3 ListObjectsV2-with-delimiter
    /// semantics: a key whose remainder after `prefix` contains the delimiter
    /// collapses into a single `common_prefixes` entry (`prefix + segment +
    /// delimiter`, the "folder" at this level); only keys with no further delimiter
    /// are returned as `objects`. Folders and objects share one sorted keyspace, so
    /// a page is the smallest `max_keys` of their merged order and `start_after`
    /// resumes after the previous page's last ENTRY (object key or folder marker).
    ///
    /// Bounded: O(max_keys) memory and index rows read, however many keys a folder
    /// holds.
    pub async fn list_v2(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListV2Page> {
        validate_bucket(bucket)?;
        let max_keys = max_keys.clamp(1, 1000);
        // Never closed, so this only ever waits.
        let _scan = self.inner.list_permits.acquire().await;
        let (bucket, prefix) = (bucket.to_string(), prefix.to_string());
        let delimiter = delimiter.map(str::to_string);
        let start_after = start_after.map(str::to_string);
        self.ix(move |ix| {
            ix.list(
                &bucket,
                &prefix,
                delimiter.as_deref(),
                start_after.as_deref(),
                max_keys,
            )
        })
        .await
    }

    // ---- multipart upload -------------------------------------------------

    /// Initiate a multipart upload; returns the opaque upload id.
    pub async fn create_multipart(
        &self,
        bucket: &str,
        key: &str,
        content_type: &str,
        cache_control: Option<&str>,
    ) -> Result<String> {
        validate_key(key)?;
        validate_bucket(bucket)?;
        let upload_id = new_id();
        let info = UploadInfo {
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: now_secs(),
            cache_control: cache_control.map(str::to_string),
        };
        let (bucket, uid) = (bucket.to_string(), upload_id.clone());
        self.ix(move |ix| ix.create_upload(&bucket, &uid, &info))
            .await?;
        Ok(upload_id)
    }

    /// Upload one part (number 1..=10000), streamed; returns its hex-MD5 etag.
    ///
    /// `expected_sha256`: same semantics as `put_object`.
    ///
    /// Note: `aws-chunked` bodies are stored raw / not de-framed.
    pub async fn upload_part<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        reader: R,
        expected_sha256: Option<&str>,
    ) -> Result<String> {
        self.upload_part_capped(
            bucket,
            upload_id,
            part_number,
            reader,
            expected_sha256,
            None,
        )
        .await
    }

    /// Like [`upload_part`], but `declared_len` sizes the per-part upload deadline
    /// (see [`upload_deadline`]) for large parts over a slow link.
    pub async fn upload_part_capped<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        mut reader: R,
        expected_sha256: Option<&str>,
        declared_len: Option<u64>,
    ) -> Result<String> {
        if !(1..=10_000).contains(&part_number) {
            return Err(ObjectError::InvalidArgument(format!(
                "part number {part_number}"
            )));
        }
        validate_bucket(bucket)?;
        validate_upload_id(upload_id)?;
        let (b, u) = (bucket.to_string(), upload_id.to_string());
        if !self.ix(move |ix| ix.upload_exists(&b, &u)).await? {
            return Err(ObjectError::NoSuchUpload(upload_id.to_string()));
        }
        let (id, size, md5) = self
            .write_segment(&mut reader, expected_sha256, declared_len)
            .await?;
        let row = PartRow {
            segment: id.clone(),
            size,
            md5: hex(&md5),
        };
        let (b, u) = (bucket.to_string(), upload_id.to_string());
        // Aborted (or completed) while the part streamed: let the segment go.
        if let Err(e) = self
            .ix(move |ix| ix.commit_part(&b, &u, part_number, &row, now_secs(), false))
            .await
        {
            self.discard(id).await;
            return Err(e);
        }
        Ok(hex(&md5))
    }

    /// Complete a multipart upload. The object is the listed parts' segments in order —
    /// no byte is copied — with the S3 multipart etag `md5(concat of the part md5s)-<count>`.
    /// Parts must be listed in ascending order, as S3 requires.
    pub async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_numbers: &[u32],
    ) -> Result<ObjectMeta> {
        validate_key(key)?;
        validate_bucket(bucket)?;
        validate_upload_id(upload_id)?;
        let (b, k, u) = (bucket.to_string(), key.to_string(), upload_id.to_string());
        let pns = part_numbers.to_vec();
        self.ix(move |ix| ix.complete_upload(&b, &k, &u, &pns, now_secs()))
            .await
    }

    /// Abort a multipart upload, discarding its staged parts.
    pub async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> Result<()> {
        validate_bucket(bucket)?;
        validate_upload_id(upload_id)?;
        let (b, u) = (bucket.to_string(), upload_id.to_string());
        self.ix(move |ix| ix.abort_upload(&b, &u, now_secs())).await
    }

    /// List all pending multipart uploads in `bucket`, by upload id.
    pub async fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<MultipartUpload>> {
        validate_bucket(bucket)?;
        let bucket = bucket.to_string();
        self.ix(move |ix| ix.list_uploads(&bucket)).await
    }

    /// Abort uploads initiated more than `max_age` ago, then reclaim every segment that
    /// is due (see [`collect_garbage`](Self::collect_garbage)). Returns the number of
    /// uploads aborted. Driven by the server's sweeper on boot + a timer.
    pub async fn sweep_stale_uploads(&self, max_age: Duration) -> Result<usize> {
        let threshold = now_secs().saturating_sub(max_age.as_secs());
        let n = self
            .ix(move |ix| ix.abort_uploads_before(threshold, now_secs()))
            .await?;
        self.collect_garbage().await?;
        Ok(n)
    }

    /// `(buckets, objects)` in this store — O(1), read from the index. Used by the
    /// server's per-project count quota.
    pub async fn usage_counts(&self) -> Result<(u64, u64)> {
        self.ix(|ix| ix.counts()).await
    }

    /// In-flight multipart uploads across all buckets, capped at `cap`.
    pub async fn count_inflight_uploads(&self, cap: u64) -> Result<u64> {
        Ok(self.ix(|ix| ix.upload_count()).await?.min(cap))
    }
}

/// Shared write loop for `put_object` and `upload_part`. Streams `reader` into `w`,
/// enforcing the per-read idle timeout and the total upload deadline, computing MD5
/// (etag) and SHA-256 (content binding) as it goes, and commits the segment only once
/// the body is complete and verified. Returns `(size, raw_md5)`.
async fn write_stream<R: AsyncRead + Unpin>(
    mut w: Box<dyn SegmentWriter>,
    reader: &mut R,
    expected_sha256: Option<&str>,
    declared_len: Option<u64>,
) -> Result<(u64, Vec<u8>)> {
    let mut md5_hasher: Md5 = Md5::new();
    let mut sha_hasher: Sha256 = Sha256::new();
    let mut size = 0u64;
    let deadline = Instant::now() + upload_deadline(declared_len);

    let mut buf = vec![0u8; 256 * 1024];
    loop {
        if Instant::now() >= deadline {
            return Err(ObjectError::Timeout("total upload time exceeded".into()));
        }
        let n = match tokio::time::timeout(IDLE_TIMEOUT, reader.read(&mut buf)).await {
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e.into()),
            Err(_) => return Err(ObjectError::Timeout("idle read timeout".into())),
        };
        if n == 0 {
            break;
        }
        md5_hasher.update(&buf[..n]);
        sha_hasher.update(&buf[..n]);
        w.write(&buf[..n]).await?;
        size += n as u64;
    }

    if let Some(exp) = expected_sha256 {
        let actual = hex(&sha_hasher.finalize());
        if actual != exp.to_lowercase() {
            return Err(ObjectError::ContentSha256Mismatch);
        }
    }
    w.commit().await?;
    Ok((size, md5_hasher.finalize().to_vec()))
}

fn file_ident(p: &Path) -> std::io::Result<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    let m = std::fs::metadata(p)?;
    Ok((m.dev(), m.ino()))
}

pub(crate) fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A fresh opaque id (lowercase hex) for a segment or an upload: time, process and a
/// per-process sequence, so unique on this host. Never derived from content (no
/// cross-tenant dedup oracle) and never from tenant input.
pub(crate) fn new_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{nanos:032x}{:08x}{:08x}",
        std::process::id(),
        SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

fn validate_upload_id(id: &str) -> Result<()> {
    if !id.is_empty() && id.len() <= 64 && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ObjectError::InvalidArgument(format!(
            "invalid upload id {id:?}"
        )))
    }
}

/// S3 bucket naming (simplified): 3–63 chars, lowercase letters/digits/hyphen, not
/// starting or ending with a hyphen.
pub(crate) fn validate_bucket(bucket: &str) -> Result<()> {
    let ok = (3..=63).contains(&bucket.len())
        && bucket
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !bucket.starts_with('-')
        && !bucket.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(ObjectError::InvalidBucketName(bucket.to_string()))
    }
}

/// Object keys: 1–1024 bytes (the S3 limit), UTF-8 (guaranteed by `&str`), no NUL (the
/// index separates bucket from key with one). A key never becomes a path or a byte-store
/// name — the segment store only sees engine-minted ids.
pub(crate) fn validate_key(key: &str) -> Result<()> {
    if (1..=1024).contains(&key.len()) && !key.contains('\0') {
        Ok(())
    } else {
        Err(ObjectError::InvalidKey(key.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn root(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-obj-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    async fn read_all(body: ObjectBody) -> Vec<u8> {
        let chunks: Vec<_> = body.into_stream().try_collect().await.unwrap();
        chunks.concat()
    }

    #[tokio::test]
    async fn put_get_head_delete_round_trip() {
        let dir = root("rt");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("my-bucket").await.unwrap();
        let body = b"hello object store";
        let meta = s
            .put_object("my-bucket", "a/b/c.txt", &body[..], "text/plain", None)
            .await
            .unwrap();
        assert_eq!(meta.size, body.len() as u64);
        // S3 etag = hex md5 of the bytes.
        assert_eq!(meta.etag, format!("{:x}", Md5::digest(body)));

        let (m2, f) = s.get_object("my-bucket", "a/b/c.txt").await.unwrap();
        assert_eq!(m2, meta);
        assert_eq!(read_all(f).await, body);
        assert_eq!(
            s.head_object("my-bucket", "a/b/c.txt")
                .await
                .unwrap()
                .content_type,
            "text/plain"
        );

        s.delete_object("my-bucket", "a/b/c.txt").await.unwrap();
        assert!(matches!(
            s.head_object("my-bucket", "a/b/c.txt").await,
            Err(ObjectError::NoSuchKey(_))
        ));
        // Delete is idempotent.
        s.delete_object("my-bucket", "a/b/c.txt").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn flat_keyspace_no_file_dir_conflict() {
        let dir = root("flat");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("flatbucket").await.unwrap();
        // In a hierarchical FS `a/b` and `a/b/c` would conflict; hex keys avoid it.
        s.put_object("flatbucket", "a/b", &b"1"[..], "x", None)
            .await
            .unwrap();
        s.put_object("flatbucket", "a/b/c", &b"2"[..], "x", None)
            .await
            .unwrap();
        assert_eq!(
            read_all(s.get_object("flatbucket", "a/b").await.unwrap().1).await,
            b"1"
        );
        assert_eq!(
            read_all(s.get_object("flatbucket", "a/b/c").await.unwrap().1).await,
            b"2"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_is_prefix_filtered_and_bucket_isolated() {
        let dir = root("list");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bucket-one").await.unwrap();
        s.create_bucket("bucket-two").await.unwrap();
        s.put_object("bucket-one", "img/a", &b"x"[..], "x", None)
            .await
            .unwrap();
        s.put_object("bucket-one", "img/b", &b"x"[..], "x", None)
            .await
            .unwrap();
        s.put_object("bucket-one", "doc/c", &b"x"[..], "x", None)
            .await
            .unwrap();
        s.put_object("bucket-two", "img/z", &b"x"[..], "x", None)
            .await
            .unwrap();

        let page = s
            .list_objects("bucket-one", "img/", None, 1000)
            .await
            .unwrap();
        let keys: Vec<_> = page.objects.into_iter().map(|m| m.key).collect();
        assert_eq!(keys, vec!["img/a".to_string(), "img/b".to_string()]);
        // Isolation: b2's object never shows up under b1.
        assert_eq!(
            s.list_objects("bucket-two", "", None, 1000)
                .await
                .unwrap()
                .objects
                .len(),
            1
        );
    }

    #[tokio::test]
    async fn list_pagination() {
        let dir = root("page");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("page-bucket").await.unwrap();
        for i in 0..5u32 {
            s.put_object("page-bucket", &format!("k{i}"), &b"x"[..], "x", None)
                .await
                .unwrap();
        }
        let p1 = s.list_objects("page-bucket", "", None, 3).await.unwrap();
        assert_eq!(p1.objects.len(), 3);
        assert!(p1.is_truncated);
        let token = p1.next_continuation_token.unwrap();
        assert_eq!(token, "k2");

        let p2 = s
            .list_objects("page-bucket", "", Some(&token), 3)
            .await
            .unwrap();
        assert_eq!(p2.objects.len(), 2);
        assert!(!p2.is_truncated);
        assert!(p2.next_continuation_token.is_none());

        let all_keys: Vec<_> = p1
            .objects
            .iter()
            .chain(p2.objects.iter())
            .map(|m| m.key.clone())
            .collect();
        assert_eq!(all_keys, vec!["k0", "k1", "k2", "k3", "k4"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_v2_delimiter_folds_folders() {
        let dir = root("delim");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("buk").await.unwrap();
        // A mix of "files" at the root level and keys nested under folders.
        for k in ["root.txt", "a/1", "a/2", "a/3", "b/x", "b/y", "zeta.txt"] {
            s.put_object("buk", k, &b"x"[..], "x", None).await.unwrap();
        }
        let page = s.list_v2("buk", "", Some("/"), None, 1000).await.unwrap();
        // Folders folded; only top-level files listed as objects.
        let objs: Vec<_> = page.objects.iter().map(|m| m.key.clone()).collect();
        assert_eq!(objs, vec!["root.txt".to_string(), "zeta.txt".to_string()]);
        assert_eq!(
            page.common_prefixes,
            vec!["a/".to_string(), "b/".to_string()]
        );
        assert!(!page.is_truncated);

        // Descend into folder "a/": its members become the objects, no sub-folders.
        let sub = s.list_v2("buk", "a/", Some("/"), None, 1000).await.unwrap();
        let sub_objs: Vec<_> = sub.objects.iter().map(|m| m.key.clone()).collect();
        assert_eq!(
            sub_objs,
            vec!["a/1".to_string(), "a/2".to_string(), "a/3".to_string()]
        );
        assert!(sub.common_prefixes.is_empty());

        // Nested folders one level down are folded, not flattened.
        s.put_object("buk", "a/deep/z", &b"x"[..], "x", None)
            .await
            .unwrap();
        let sub2 = s.list_v2("buk", "a/", Some("/"), None, 1000).await.unwrap();
        assert_eq!(sub2.common_prefixes, vec!["a/deep/".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_deadline_is_size_aware_clamped_to_floor_and_ceiling() {
        // Unknown / small uploads get the floor; a large declared length scales the
        // budget; a hostile huge declared length is bounded by the ceiling (so it
        // can't be used to hold a connection open for days/years).
        assert_eq!(upload_deadline(None), MIN_UPLOAD_DEADLINE);
        assert_eq!(upload_deadline(Some(1024)), MIN_UPLOAD_DEADLINE); // tiny -> floor
        assert_eq!(upload_deadline(Some(0)), MIN_UPLOAD_DEADLINE);
        // 16 GiB (the default quota) at the 1 MiB/s floor rate = 16384s: above the
        // floor, below the 6h ceiling -> used as-is.
        let dq = 16u64 * 1024 * 1024 * 1024;
        assert_eq!(
            upload_deadline(Some(dq)),
            Duration::from_secs(dq / MIN_UPLOAD_RATE)
        );
        assert!(upload_deadline(Some(dq)) > MIN_UPLOAD_DEADLINE);
        assert!(upload_deadline(Some(dq)) <= MAX_UPLOAD_DEADLINE);
        // A hostile / large-quota declared length is clamped to the ceiling, NOT years.
        assert_eq!(upload_deadline(Some(u64::MAX)), MAX_UPLOAD_DEADLINE);
        assert_eq!(upload_deadline(Some(1024u64.pow(5))), MAX_UPLOAD_DEADLINE); // 1 PiB
    }

    #[tokio::test]
    async fn list_v2_folder_marker_key_folds_like_s3() {
        // A key that ENDS in the delimiter (a zero-byte "folder marker", e.g. "dir/")
        // folds into the common prefix "dir/" at the parent level — it is NOT listed
        // as an object there. This matches AWS S3 ListObjectsV2 semantics exactly.
        // Descending into the folder (prefix="dir/") then surfaces the marker object.
        let dir = root("marker");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("buk").await.unwrap();
        s.put_object("buk", "dir/", &b""[..], "x", None)
            .await
            .unwrap();
        s.put_object("buk", "dir/file", &b"x"[..], "x", None)
            .await
            .unwrap();

        let root_page = s.list_v2("buk", "", Some("/"), None, 1000).await.unwrap();
        assert!(
            root_page.objects.is_empty(),
            "marker must not list as a root object"
        );
        assert_eq!(root_page.common_prefixes, vec!["dir/".to_string()]);

        // Inside the folder, the marker object (remainder "" has no delimiter) appears.
        let sub = s
            .list_v2("buk", "dir/", Some("/"), None, 1000)
            .await
            .unwrap();
        let keys: Vec<_> = sub.objects.iter().map(|m| m.key.clone()).collect();
        assert_eq!(keys, vec!["dir/".to_string(), "dir/file".to_string()]);
        assert!(sub.common_prefixes.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_v2_delimiter_pagination_skips_emitted_folder() {
        // The continuation token can be a FOLDER marker; the next page must skip the
        // whole folder even though its member keys sort after the marker string.
        let dir = root("delim-page");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("buk").await.unwrap();
        // Sorted entry order at root with delimiter "/": "a/", "b/", "c.txt", "d/".
        for k in ["a/1", "a/2", "b/1", "b/2", "b/3", "c.txt", "d/1"] {
            s.put_object("buk", k, &b"x"[..], "x", None).await.unwrap();
        }
        // Page 1: two entries → folders "a/" and "b/"; truncated, token = "b/".
        let p1 = s.list_v2("buk", "", Some("/"), None, 2).await.unwrap();
        assert_eq!(p1.common_prefixes, vec!["a/".to_string(), "b/".to_string()]);
        assert!(p1.objects.is_empty());
        assert!(p1.is_truncated);
        let token = p1.next_continuation_token.clone().unwrap();
        assert_eq!(token, "b/");

        // Page 2 must NOT re-list "b/" even though "b/1".."b/3" > "b/" lexically.
        let p2 = s
            .list_v2("buk", "", Some("/"), Some(&token), 2)
            .await
            .unwrap();
        assert_eq!(p2.common_prefixes, vec!["d/".to_string()]);
        assert_eq!(
            p2.objects.iter().map(|m| m.key.clone()).collect::<Vec<_>>(),
            vec!["c.txt".to_string()]
        );
        assert!(!p2.is_truncated);
        assert!(p2.next_continuation_token.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn errors_for_missing_bucket_and_invalid_names() {
        let dir = root("err");
        let s = ObjectStore::open(&dir).unwrap();
        assert!(matches!(
            s.put_object("nope", "k", &b""[..], "x", None).await,
            Err(ObjectError::NoSuchBucket(_))
        ));
        assert!(matches!(
            s.create_bucket("AB").await,
            Err(ObjectError::InvalidBucketName(_))
        )); // too short + uppercase
        s.create_bucket("ok-bucket").await.unwrap();
        assert!(matches!(
            s.create_bucket("ok-bucket").await,
            Err(ObjectError::BucketAlreadyExists(_))
        ));
        s.put_object("ok-bucket", "k", &b"x"[..], "x", None)
            .await
            .unwrap();
        assert!(matches!(
            s.delete_bucket("ok-bucket").await,
            Err(ObjectError::BucketNotEmpty(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_concatenates_parts_in_order() {
        let dir = root("mpu");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("mp-bucket").await.unwrap();
        let uid = s
            .create_multipart("mp-bucket", "big/file", "application/octet-stream", None)
            .await
            .unwrap();
        let e1 = s
            .upload_part("mp-bucket", &uid, 1, &b"hello "[..], None)
            .await
            .unwrap();
        let e2 = s
            .upload_part("mp-bucket", &uid, 2, &b"world"[..], None)
            .await
            .unwrap();
        assert_eq!(e1, format!("{:x}", Md5::digest(b"hello ")));
        assert_eq!(e2, format!("{:x}", Md5::digest(b"world")));

        let meta = s
            .complete_multipart("mp-bucket", "big/file", &uid, &[1, 2])
            .await
            .unwrap();
        assert_eq!(meta.size, 11);
        assert!(meta.etag.ends_with("-2")); // S3 multipart etag carries the part count
        assert_eq!(
            read_all(s.get_object("mp-bucket", "big/file").await.unwrap().1).await,
            b"hello world"
        );

        // The upload id is consumed by complete.
        assert!(matches!(
            s.upload_part("mp-bucket", &uid, 3, &b"x"[..], None).await,
            Err(ObjectError::NoSuchUpload(_))
        ));
        // Bucket can still be emptied + deleted (the .uploads dir was cleaned up).
        s.delete_object("mp-bucket", "big/file").await.unwrap();
        s.delete_bucket("mp-bucket").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_abort_discards_parts() {
        let dir = root("mpu-abort");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("ab-bucket").await.unwrap();
        let uid = s
            .create_multipart("ab-bucket", "k", "x", None)
            .await
            .unwrap();
        s.upload_part("ab-bucket", &uid, 1, &b"data"[..], None)
            .await
            .unwrap();
        s.abort_multipart("ab-bucket", &uid).await.unwrap();
        assert!(matches!(
            s.complete_multipart("ab-bucket", "k", &uid, &[1]).await,
            Err(ObjectError::NoSuchUpload(_))
        ));
        assert!(matches!(
            s.head_object("ab-bucket", "k").await,
            Err(ObjectError::NoSuchKey(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_list_and_sweep() {
        let dir = root("mpu-list");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("sweep-bucket").await.unwrap();
        let uid = s
            .create_multipart(
                "sweep-bucket",
                "pending/obj",
                "application/octet-stream",
                None,
            )
            .await
            .unwrap();
        s.upload_part("sweep-bucket", &uid, 1, &b"part"[..], None)
            .await
            .unwrap();

        let uploads = s.list_multipart_uploads("sweep-bucket").await.unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].upload_id, uid);
        assert_eq!(uploads[0].key, "pending/obj");

        // Zero seconds max_age -> everything is "stale" (initiated <= now - 0 = now).
        // Use 1s so freshly created upload IS stale only when initiated < now.
        // Force stale by using a tiny threshold: max_age = u64::MAX seconds.
        let removed = s
            .sweep_stale_uploads(Duration::from_secs(u64::MAX / 2))
            .await
            .unwrap();
        // Not stale (just created) — no removal.
        assert_eq!(removed, 0);

        // With max_age=0 every upload is stale.
        let removed = s.sweep_stale_uploads(Duration::from_secs(0)).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(
            s.list_multipart_uploads("sweep-bucket")
                .await
                .unwrap()
                .len(),
            0
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn content_sha256_binding() {
        use sha2::{Digest as Sha2Digest, Sha256};
        let dir = root("sha256");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("sha-bucket").await.unwrap();
        let body = b"content to verify";
        let correct = format!("{:x}", Sha256::digest(body));
        // Correct hash -> succeeds.
        s.put_object("sha-bucket", "k", &body[..], "x", Some(&correct))
            .await
            .unwrap();
        // Wrong hash -> ContentSha256Mismatch.
        assert!(matches!(
            s.put_object("sha-bucket", "k", &body[..], "x", Some("aaaa"))
                .await,
            Err(ObjectError::ContentSha256Mismatch)
        ));
        // None -> no check.
        s.put_object("sha-bucket", "k", &body[..], "x", None)
            .await
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- long keys --------------------------------------------------------

    /// A key of exactly `n` bytes with a recognisable shape.
    fn key_of(n: usize, tag: &str) -> String {
        let mut k = format!("bundle-inputs/{tag}/");
        while k.len() < n {
            k.push('x');
        }
        k.truncate(n);
        k
    }
    #[tokio::test]
    async fn keys_up_to_the_s3_limit_round_trip() {
        let dir = root("longkeys");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        // Either side of every boundary the layout-1 file names had, and the S3 limit.
        for n in [
            1, 116, 117, 123, 124, 125, 126, 127, 186, 187, 255, 512, 1024,
        ] {
            let key = key_of(n, "a");
            let body = format!("body-{n}");
            let meta = s
                .put_object("bkt", &key, body.as_bytes(), "text/plain", None)
                .await
                .unwrap_or_else(|e| panic!("put {n}-byte key: {e}"));
            assert_eq!(meta.key, key);
            let (got, f) = s.get_object("bkt", &key).await.unwrap();
            assert_eq!(got.key, key);
            assert_eq!(read_all(f).await, body.as_bytes(), "{n}-byte key");
            assert_eq!(
                s.head_object("bkt", &key).await.unwrap().size,
                body.len() as u64
            );
        }
        assert_eq!(s.usage_counts().await.unwrap(), (1, 13));

        // One past the limit is a clean InvalidKey on every path — never an I/O error.
        let over = key_of(1025, "a");
        assert!(matches!(
            s.put_object("bkt", &over, &b"x"[..], "t", None).await,
            Err(ObjectError::InvalidKey(_))
        ));
        assert!(matches!(
            s.get_object("bkt", &over).await,
            Err(ObjectError::InvalidKey(_))
        ));
        assert!(matches!(
            s.create_multipart("bkt", &over, "t", None).await,
            Err(ObjectError::InvalidKey(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn long_keys_overwrite_delete_and_multipart() {
        let dir = root("longops");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let key = key_of(700, "a");
        s.put_object("bkt", &key, &b"one"[..], "t", None)
            .await
            .unwrap();
        s.put_object("bkt", &key, &b"two!"[..], "t", None)
            .await
            .unwrap();
        assert_eq!(s.usage_counts().await.unwrap(), (1, 1));
        assert_eq!(s.object_size("bkt", &key).await.unwrap(), Some(4));
        s.delete_object("bkt", &key).await.unwrap();
        assert!(matches!(
            s.get_object("bkt", &key).await,
            Err(ObjectError::NoSuchKey(_))
        ));

        let mp = key_of(1024, "mp");
        let id = s.create_multipart("bkt", &mp, "t", None).await.unwrap();
        s.upload_part("bkt", &id, 1, &b"hello "[..], None)
            .await
            .unwrap();
        s.upload_part("bkt", &id, 2, &b"world"[..], None)
            .await
            .unwrap();
        s.complete_multipart("bkt", &mp, &id, &[1, 2])
            .await
            .unwrap();
        assert_eq!(
            read_all(s.get_object("bkt", &mp).await.unwrap().1).await,
            b"hello world"
        );
        s.delete_object("bkt", &mp).await.unwrap();
        s.delete_bucket("bkt").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- index/segments split ---------------------------------------------

    /// Segment ids currently in the index's pending / garbage tables.
    fn tracked(s: &ObjectStore, now: u64) -> Vec<String> {
        let mut v = s.inner.index.due_segments(now).unwrap();
        v.sort();
        v
    }

    fn row(s: &ObjectStore, bucket: &str, key: &str) -> ObjectRow {
        s.inner.index.get_object(bucket, key).unwrap()
    }

    fn local(dir: &Path) -> LocalSegments {
        LocalSegments::open(dir.join(SEGMENTS_DIR)).unwrap()
    }

    /// A completed multipart object IS its parts' segments — nothing was copied — and a
    /// ranged read across part boundaries returns exactly the right bytes.
    #[tokio::test]
    async fn multipart_is_a_manifest_and_ranges_span_segments() {
        let dir = root("manifest");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let parts: [&[u8]; 3] = [b"abcdefg", b"hij", b"klmnopqrstu"];
        let uid = s.create_multipart("bkt", "m", "t", None).await.unwrap();
        for (i, p) in parts.iter().enumerate() {
            s.upload_part("bkt", &uid, i as u32 + 1, *p, None)
                .await
                .unwrap();
        }
        // An unused part is retired at complete, not left referenced.
        s.upload_part("bkt", &uid, 9, &b"unused"[..], None)
            .await
            .unwrap();
        s.complete_multipart("bkt", "m", &uid, &[1, 2, 3])
            .await
            .unwrap();
        let r = row(&s, "bkt", "m");
        assert_eq!(
            r.segments.iter().map(|g| g.size).collect::<Vec<_>>(),
            [7, 3, 11]
        );
        let whole: Vec<u8> = parts.concat();
        for start in 0..whole.len() as u64 {
            for len in 0..=(whole.len() as u64 - start) {
                let (_, body) = s.get_object("bkt", "m").await.unwrap();
                let got: Vec<_> = body.stream(start, len).try_collect().await.unwrap();
                assert_eq!(
                    got.concat(),
                    &whole[start as usize..(start + len) as usize],
                    "[{start}, +{len})"
                );
            }
        }
        // Only the unused part is garbage.
        assert_eq!(tracked(&s, u64::MAX).len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn complete_requires_ascending_parts() {
        let dir = root("mp-order");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let uid = s.create_multipart("bkt", "k", "t", None).await.unwrap();
        s.upload_part("bkt", &uid, 1, &b"a"[..], None)
            .await
            .unwrap();
        s.upload_part("bkt", &uid, 2, &b"b"[..], None)
            .await
            .unwrap();
        for bad in [&[2, 1][..], &[1, 1, 2][..]] {
            assert!(matches!(
                s.complete_multipart("bkt", "k", &uid, bad).await,
                Err(ObjectError::InvalidArgument(_))
            ));
        }
        // A refused complete changed nothing: the upload still completes.
        s.complete_multipart("bkt", "k", &uid, &[1, 2])
            .await
            .unwrap();
        assert_eq!(
            read_all(s.get_object("bkt", "k").await.unwrap().1).await,
            b"ab"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bucket_with_an_unfinished_upload_is_not_empty() {
        let dir = root("busy-bucket");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let uid = s.create_multipart("bkt", "k", "t", None).await.unwrap();
        assert!(matches!(
            s.delete_bucket("bkt").await,
            Err(ObjectError::BucketNotEmpty(_))
        ));
        s.abort_multipart("bkt", &uid).await.unwrap();
        s.delete_bucket("bkt").await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A GET that looked an object up keeps reading THAT version after an overwrite or
    /// delete (its segments are only garbage, not gone), and the reclaim happens once the
    /// grace has passed.
    #[tokio::test]
    async fn readers_keep_their_version_and_garbage_waits_out_the_grace() {
        let dir = root("grace");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        s.put_object("bkt", "k", &b"old"[..], "t", None)
            .await
            .unwrap();
        let old_seg = row(&s, "bkt", "k").segments[0].id.clone();
        let (_, before) = s.get_object("bkt", "k").await.unwrap();
        s.put_object("bkt", "k", &b"new!"[..], "t", None)
            .await
            .unwrap();
        assert_eq!(read_all(before).await, b"old");
        assert_eq!(
            read_all(s.get_object("bkt", "k").await.unwrap().1).await,
            b"new!"
        );

        // Not due yet: a sweep now reclaims nothing.
        assert_eq!(s.collect_garbage().await.unwrap(), 0);
        assert!(local(&dir).exists(&old_seg));
        let now = now_secs();
        assert!(tracked(&s, now).is_empty());
        assert_eq!(
            tracked(&s, now + crate::index::GRACE),
            vec![old_seg.clone()]
        );

        // Delete: the live segment is retired the same way.
        let new_seg = row(&s, "bkt", "k").segments[0].id.clone();
        s.delete_object("bkt", "k").await.unwrap();
        let mut both = vec![old_seg.clone(), new_seg.clone()];
        both.sort();
        assert_eq!(tracked(&s, now + crate::index::GRACE), both);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A write whose process died between "pending" and its commit is reclaimed once it
    /// is past the orphan age, and never before; a commit that finds its pending row gone
    /// refuses to reference the segment.
    #[tokio::test]
    async fn crashed_writes_are_reclaimed_after_the_orphan_age() {
        let dir = root("orphan");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let now = now_secs();
        let (fresh, dead) = (new_id(), new_id());
        s.inner.index.add_pending(&fresh, now).unwrap();
        s.inner
            .index
            .add_pending(&dead, now - crate::index::PENDING_ORPHAN_AGE - 1)
            .unwrap();
        for id in [&fresh, &dead] {
            let mut w = s.inner.segments.create(id).await.unwrap();
            w.write(b"bytes").await.unwrap();
            w.commit().await.unwrap();
        }
        assert_eq!(s.collect_garbage().await.unwrap(), 1);
        assert!(!local(&dir).exists(&dead) && local(&dir).exists(&fresh));

        // Referencing a reclaimed segment is refused.
        let r = ObjectRow {
            meta: ObjectMeta {
                key: "k".into(),
                size: 5,
                etag: "e".into(),
                content_type: "t".into(),
                last_modified: now,
                cache_control: None,
            },
            segments: vec![SegRef { id: dead, size: 5 }],
        };
        assert!(s.inner.index.commit_object("bkt", &r, now, false).is_err());
        assert!(matches!(
            s.head_object("bkt", "k").await,
            Err(ObjectError::NoSuchKey(_))
        ));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A failed write (bad checksum, bucket gone) leaves no pending row behind: its
    /// segment is garbage due immediately.
    #[tokio::test]
    async fn failed_writes_release_their_segment() {
        let dir = root("failed-write");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        assert!(matches!(
            s.put_object("bkt", "k", &b"body"[..], "t", Some(&"0".repeat(64)))
                .await,
            Err(ObjectError::ContentSha256Mismatch)
        ));
        // The checksum failed before commit, so no segment exists; its id is garbage now.
        assert_eq!(tracked(&s, now_secs()).len(), 1);
        assert_eq!(s.collect_garbage().await.unwrap(), 1);
        assert!(tracked(&s, u64::MAX).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Deleting a store's root under an open handle (project deleted and re-registered
    /// with the same id) makes the handle stale; reopening gives a fresh, empty store
    /// instead of the old incarnation's unlinked index.
    #[tokio::test]
    async fn a_recreated_root_is_a_new_store() {
        let dir = root("recreate");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        assert!(s.is_current());
        assert!(Arc::ptr_eq(
            &s.inner,
            &ObjectStore::open(&dir).unwrap().inner
        ));
        std::fs::remove_dir_all(&dir).unwrap();
        assert!(!s.is_current());
        let fresh = ObjectStore::open(&dir).unwrap();
        assert!(fresh.is_current() && !Arc::ptr_eq(&s.inner, &fresh.inner));
        assert!(fresh.list_buckets().await.unwrap().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    // ---- layout-1 migration -----------------------------------------------

    fn legacy_object(dir: &Path, bucket: &str, key: &str, body: &[u8]) {
        let b = dir.join(bucket);
        std::fs::create_dir_all(&b).unwrap();
        let stem = crate::legacy::object_stem(key);
        std::fs::write(b.join(&stem), body).unwrap();
        let meta = ObjectMeta {
            key: key.to_string(),
            size: body.len() as u64,
            etag: hex(&Md5::digest(body)),
            content_type: "text/plain".into(),
            last_modified: 1,
            cache_control: Some("max-age=60".into()),
        };
        std::fs::write(
            b.join(format!("{stem}.meta")),
            serde_json::to_vec(&meta).unwrap(),
        )
        .unwrap();
    }

    /// A layout-1 store (all three file-name tiers, an in-flight multipart upload, a CORS
    /// sidecar, temp junk) opens as the same store: same keys, bytes and metadata, the
    /// upload still completes, and the legacy tree is gone.
    #[tokio::test]
    async fn a_layout_one_store_migrates_on_open() {
        let dir = root("migrate");
        std::fs::create_dir_all(&dir).unwrap();
        let keys = ["a.txt".to_string(), key_of(150, "b64"), key_of(900, "hash")];
        for k in &keys {
            legacy_object(&dir, "bkt", k, k.as_bytes());
        }
        std::fs::create_dir_all(dir.join("empty-bucket")).unwrap();
        std::fs::write(dir.join("bkt").join(".tmp.1.2"), b"junk").unwrap();
        let cors = r#"{"rules":[]}"#;
        std::fs::create_dir_all(dir.join(".cors")).unwrap();
        std::fs::write(dir.join(".cors").join("bkt.json"), cors).unwrap();
        let up = dir.join("bkt").join(".uploads").join("00ab");
        std::fs::create_dir_all(&up).unwrap();
        std::fs::write(
            up.join("info.json"),
            serde_json::to_vec(&UploadInfo {
                key: "mp".into(),
                content_type: "t".into(),
                initiated: 0,
                cache_control: None,
            })
            .unwrap(),
        )
        .unwrap();
        std::fs::write(up.join("part-1"), b"hello ").unwrap();
        std::fs::write(up.join("part-1.md5"), Md5::digest(b"hello ")).unwrap();

        let s = ObjectStore::open(&dir).unwrap();
        assert_eq!(s.list_buckets().await.unwrap(), ["bkt", "empty-bucket"]);
        for k in &keys {
            let (meta, body) = s.get_object("bkt", k).await.unwrap();
            assert_eq!(&meta.key, k);
            assert_eq!(meta.size, k.len() as u64);
            assert_eq!(meta.cache_control.as_deref(), Some("max-age=60"));
            assert_eq!(read_all(body).await, k.as_bytes());
        }
        assert_eq!(s.usage_counts().await.unwrap(), (2, 3));
        assert!(s.get_bucket_cors("bkt").await.unwrap().is_some());
        let uploads = s.list_multipart_uploads("bkt").await.unwrap();
        assert_eq!((uploads.len(), uploads[0].key.as_str()), (1, "mp"));
        assert!(uploads[0].initiated > 0, "legacy upload got its mtime");
        s.upload_part("bkt", "00ab", 2, &b"world"[..], None)
            .await
            .unwrap();
        s.complete_multipart("bkt", "mp", "00ab", &[1, 2])
            .await
            .unwrap();
        assert_eq!(
            read_all(s.get_object("bkt", "mp").await.unwrap().1).await,
            b"hello world"
        );

        // Nothing of layout 1 is left.
        let mut left: Vec<String> = std::fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(left, [INDEX_FILE, SEGMENTS_DIR]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A migration interrupted after committing some rows but before unlinking their
    /// legacy files re-runs cleanly: the committed version wins, no object is doubled,
    /// and the redundant segment is garbage.
    #[tokio::test]
    async fn an_interrupted_migration_reruns_cleanly() {
        let dir = root("migrate-twice");
        std::fs::create_dir_all(&dir).unwrap();
        legacy_object(&dir, "bkt", "k", b"first");
        drop(ObjectStore::open(&dir).unwrap());
        // As if the first run died before unlinking (and before stamping the layout).
        legacy_object(&dir, "bkt", "k", b"first");
        {
            let ix = Index::open(&dir.join(INDEX_FILE)).unwrap();
            ix.set_layout(1).unwrap();
        }
        let s = ObjectStore::open(&dir).unwrap();
        assert_eq!(s.usage_counts().await.unwrap(), (1, 1));
        assert_eq!(
            read_all(s.get_object("bkt", "k").await.unwrap().1).await,
            b"first"
        );
        assert_eq!(
            tracked(&s, now_secs()).len(),
            1,
            "the redundant link is garbage"
        );
        assert!(!dir.join("bkt").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Only a sidecar under its own key's name was ever served; one that isn't (or that
    /// doesn't parse) is not migrated — and not deleted: it stays where it was.
    #[tokio::test]
    async fn unreadable_legacy_objects_stay_in_place() {
        let dir = root("migrate-bad");
        std::fs::create_dir_all(&dir).unwrap();
        let (a, b) = (key_of(300, "a"), key_of(300, "b"));
        legacy_object(&dir, "bkt", &a, b"A");
        legacy_object(&dir, "bkt", "fine", b"ok");
        let (sa, sb) = (
            crate::legacy::object_stem(&a),
            crate::legacy::object_stem(&b),
        );
        for suffix in ["", ".meta"] {
            std::fs::rename(
                dir.join("bkt").join(format!("{sa}{suffix}")),
                dir.join("bkt").join(format!("{sb}{suffix}")),
            )
            .unwrap();
        }
        let s = ObjectStore::open(&dir).unwrap();
        assert!(matches!(
            s.get_object("bkt", &b).await,
            Err(ObjectError::NoSuchKey(_))
        ));
        assert!(matches!(
            s.get_object("bkt", &a).await,
            Err(ObjectError::NoSuchKey(_))
        ));
        assert_eq!(
            read_all(s.get_object("bkt", "fine").await.unwrap().1).await,
            b"ok"
        );
        assert!(dir.join("bkt").join(format!("{sb}.meta")).exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Listing over a mix of short and long keys matches a plain sort + filter of the
    /// keys, for every prefix / delimiter / page size — including prefixes longer than
    /// a hashed name's head, long keys that share one head, and a multi-byte character
    /// straddling the head's cut.
    #[tokio::test]
    async fn listing_long_keys_matches_the_flat_keyspace() {
        let s = ObjectStore::open(root("longlist")).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let shared_head = "h/".to_string() + &"s".repeat(200); // > the head, in common
        let straddle = "é".repeat(100); // the head's cut (byte 153) splits an `é`
        let mut keys: Vec<String> = vec![
            "a.txt".into(),
            "docs/readme.md".into(),
            "docs/".to_string() + &"d".repeat(200) + "/deep/file.bin",
            "docs/".to_string() + &"d".repeat(200) + "/deep/other.bin",
            "docs/".to_string() + &"e".repeat(40) + "/" + &"f".repeat(300),
            "docs/".to_string() + &"g".repeat(140), // whole-key base64 name
            "docs/".to_string() + &"g".repeat(140) + "/in/base64",
            format!("{shared_head}/one"),
            format!("{shared_head}/two"),
            format!("{shared_head}0"),
            straddle.clone(),
            straddle.clone() + "/tail",
            "z".repeat(1024),
            "z".repeat(1023) + "/",
        ];
        for i in 0..30 {
            keys.push(format!(
                "bundle-inputs/{}/{i:04}/{}.tar.gz",
                "k".repeat(40),
                "n".repeat(80)
            ));
        }
        for k in &keys {
            s.put_object("bkt", k, k.as_bytes(), "t", None)
                .await
                .unwrap();
        }
        keys.sort();

        // Reference model: the S3 flat keyspace over the sorted key list.
        let model = |prefix: &str, delim: Option<&str>| -> Vec<(String, bool)> {
            let mut out: Vec<(String, bool)> = Vec::new();
            for k in keys.iter().filter(|k| k.starts_with(prefix)) {
                let e = match delim.and_then(|d| k[prefix.len()..].find(d).map(|i| (i, d))) {
                    Some((i, d)) => (k[..prefix.len() + i + d.len()].to_string(), true),
                    None => (k.clone(), false),
                };
                if !out.contains(&e) {
                    out.push(e);
                }
            }
            out.sort();
            out
        };

        let deep = "docs/".to_string() + &"d".repeat(200) + "/";
        let prefixes = [
            "".to_string(),
            "docs/".into(),
            "bundle-inputs/".into(),
            format!("bundle-inputs/{}/00", "k".repeat(40)),
            deep.clone(),
            deep.clone() + "deep/f",
            shared_head.clone(),
            format!("{shared_head}/"),
            "é".repeat(44),
            "é".repeat(77),
            straddle.clone(),
            "docs/".to_string() + &"g".repeat(100),
            "z".repeat(1000),
            "nope/".into(),
        ];
        for prefix in &prefixes {
            for delim in [None, Some("/"), Some("deep/")] {
                for page in [1usize, 2, 7, 1000] {
                    let want = model(prefix, delim);
                    let mut got: Vec<(String, bool)> = Vec::new();
                    let mut after: Option<String> = None;
                    loop {
                        let p = s
                            .list_v2("bkt", prefix, delim, after.as_deref(), page)
                            .await
                            .unwrap();
                        let mut entries: Vec<(String, bool)> = p
                            .objects
                            .iter()
                            .map(|m| (m.key.clone(), false))
                            .chain(p.common_prefixes.iter().map(|c| (c.clone(), true)))
                            .collect();
                        entries.sort();
                        assert!(entries.len() <= page);
                        got.extend(entries);
                        if !p.is_truncated {
                            break;
                        }
                        after = p.next_continuation_token;
                        assert!(after.is_some());
                    }
                    assert_eq!(got, want, "prefix={prefix:?} delim={delim:?} page={page}");
                }
            }
        }
    }

    /// Listings of one store queue past `MAX_CONCURRENT_LISTS` instead of running at
    /// once, and all complete.
    #[tokio::test]
    async fn concurrent_listings_are_bounded_and_all_complete() {
        let s = std::sync::Arc::new(ObjectStore::open(root("listcap")).unwrap());
        s.create_bucket("bkt").await.unwrap();
        s.put_object("bkt", "a", &b"x"[..], "t", None)
            .await
            .unwrap();
        let held = s
            .inner
            .list_permits
            .acquire_many(MAX_CONCURRENT_LISTS as u32)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..3 * MAX_CONCURRENT_LISTS {
            let s = s.clone();
            tasks.spawn(async move {
                s.list_objects("bkt", "", None, 10)
                    .await
                    .unwrap()
                    .objects
                    .len()
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            tasks.try_join_next().is_none(),
            "a listing ran past the cap"
        );
        drop(held);
        while let Some(n) = tasks.join_next().await {
            assert_eq!(n.unwrap(), 1);
        }
    }
}
