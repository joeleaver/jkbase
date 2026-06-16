use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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

/// Total wall-clock budget for one upload body of `declared_len` (the declared
/// Content-Length / decoded length). `None` (length unknown) falls back to the
/// floor. Combined with [`IDLE_TIMEOUT`] per read, this bounds both stalls and
/// total hold while scaling the budget to the work.
fn upload_deadline(declared_len: Option<u64>) -> Duration {
    match declared_len {
        Some(n) => MIN_UPLOAD_DEADLINE.max(Duration::from_secs(n / MIN_UPLOAD_RATE)),
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
struct UploadInfo {
    key: String,
    content_type: String,
    /// Unix seconds at which the upload was initiated. Defaulted to 0 for
    /// uploads created before this field existed (pre-hardening).
    #[serde(default)]
    initiated: u64,
}

type Result<T> = std::result::Result<T, ObjectError>;

/// Metadata for a stored object (mirrors the S3 fields the API exposes).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct ObjectMeta {
    pub key: String,
    pub size: u64,
    /// S3 single-part etag: the hex MD5 of the object bytes (the API layer quotes it).
    pub etag: String,
    pub content_type: String,
    /// Last-modified, unix seconds.
    pub last_modified: u64,
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

/// A tenant object store rooted at `root`, one subdirectory per bucket. Each
/// object is two files: `<hex(key)>` (the bytes) and `<hex(key)>.meta` (JSON).
pub struct ObjectStore {
    root: PathBuf,
}

impl ObjectStore {
    /// Open (creating if absent) an object store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self { root })
    }

    // ---- buckets ----------------------------------------------------------

    pub async fn create_bucket(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let dir = self.root.join(bucket);
        if tokio::fs::try_exists(&dir).await? {
            return Err(ObjectError::BucketAlreadyExists(bucket.to_string()));
        }
        tokio::fs::create_dir_all(&dir).await?;
        Ok(())
    }

    pub async fn delete_bucket(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let dir = self.root.join(bucket);
        if !tokio::fs::try_exists(&dir).await? {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        // S3 refuses to delete a non-empty bucket.
        let mut rd = tokio::fs::read_dir(&dir).await?;
        if rd.next_entry().await?.is_some() {
            return Err(ObjectError::BucketNotEmpty(bucket.to_string()));
        }
        tokio::fs::remove_dir(&dir).await?;
        Ok(())
    }

    pub async fn list_buckets(&self) -> Result<Vec<String>> {
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Skip bookkeeping dirs (e.g. `.owners`); a real bucket can't start with `.`.
            if !name.starts_with('.') && entry.file_type().await?.is_dir() {
                out.push(name);
            }
        }
        out.sort();
        Ok(out)
    }

    pub async fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        validate_bucket(bucket)?;
        Ok(tokio::fs::try_exists(self.root.join(bucket)).await?)
    }

    async fn require_bucket(&self, bucket: &str) -> Result<PathBuf> {
        validate_bucket(bucket)?;
        let dir = self.root.join(bucket);
        if !tokio::fs::try_exists(&dir).await? {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        Ok(dir)
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
        self.put_object_capped(bucket, key, reader, content_type, expected_sha256, None)
            .await
    }

    /// Like [`put_object`], but `declared_len` (the declared Content-Length) sizes the
    /// total upload deadline — see [`upload_deadline`]. Authenticated front-ends pass
    /// the declared length so a large single PUT over a slow link isn't capped at the
    /// small-upload floor; plain `put_object` (unknown length) uses the floor.
    pub async fn put_object_capped<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        key: &str,
        mut reader: R,
        content_type: &str,
        expected_sha256: Option<&str>,
        declared_len: Option<u64>,
    ) -> Result<ObjectMeta> {
        validate_key(key)?;
        let dir = self.require_bucket(bucket).await?;
        let hk = hex(key.as_bytes());
        let obj = dir.join(&hk);
        let tmp = dir.join(format!(
            "{hk}.tmp.{}.{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));

        let result = write_stream(&tmp, &mut reader, expected_sha256, declared_len).await;
        match result {
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e)
            }
            Ok((size, etag, _)) => {
                if let Err(e) = tokio::fs::rename(&tmp, &obj).await {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(e.into());
                }
                let meta = ObjectMeta {
                    key: key.to_string(),
                    size,
                    etag,
                    content_type: content_type.to_string(),
                    last_modified: now_secs(),
                };
                let meta_path = dir.join(format!("{hk}.meta"));
                if let Err(e) = tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).await {
                    // Bytes are committed but unreadable without the sidecar — don't leave
                    // a quota-consuming orphan; drop both and fail.
                    let _ = tokio::fs::remove_file(&obj).await;
                    let _ = tokio::fs::remove_file(&meta_path).await;
                    return Err(e.into());
                }
                Ok(meta)
            }
        }
    }

    /// Open `bucket/key` for streaming, returning its metadata + the file handle.
    pub async fn get_object(&self, bucket: &str, key: &str) -> Result<(ObjectMeta, tokio::fs::File)> {
        let (meta, obj) = self.locate(bucket, key).await?;
        let f = tokio::fs::File::open(&obj).await?;
        Ok((meta, f))
    }

    pub async fn head_object(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        Ok(self.locate(bucket, key).await?.0)
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
        let dir = self.require_bucket(bucket).await?;
        validate_key(key)?;
        let hk = hex(key.as_bytes());
        let _ = tokio::fs::remove_file(dir.join(&hk)).await;
        let _ = tokio::fs::remove_file(dir.join(format!("{hk}.meta"))).await;
        Ok(())
    }

    /// List objects in `bucket` whose key starts with `prefix`, sorted by key.
    ///
    /// Returns a page of up to `max_keys` objects (clamped to 1..=1000).
    /// `start_after`: skip all keys ≤ this value (both V1 marker and V2
    /// continuation-token are passed here by the HTTP layer).
    ///
    /// Only reads `.meta` files for the page's keys — a million-object bucket
    /// never loads every meta into RAM. A thin delegate over [`list_v2`] with no
    /// delimiter (so `common_prefixes` is always empty).
    pub async fn list_objects(
        &self,
        bucket: &str,
        prefix: &str,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListPage> {
        let page = self.list_v2(bucket, prefix, None, start_after, max_keys).await?;
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
    /// Bounded memory: O(max_keys) regardless of bucket size — a single folder may
    /// hold millions of keys yet costs one slot — mirroring the non-delimited path.
    pub async fn list_v2(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListV2Page> {
        let max_keys = max_keys.clamp(1, 1000);
        let dir = self.require_bucket(bucket).await?;

        // A list "entry" is either an object (its key) or a folded folder (a common
        // prefix). Both sort by their string form. We keep the smallest `cap` DISTINCT
        // entries in a bounded max-heap — so per-request memory is O(max_keys), NOT
        // O(objects-in-bucket): a bucket at its object-count quota (default 1M) can't
        // amplify one list into ~100 MB of strings on the shared host. `present` holds
        // the heap's sort keys (≤ cap) so a folder generated by many keys is counted
        // once toward the page.
        let cap = max_keys + 1;

        struct Entry {
            sort_key: String,
            is_prefix: bool,
        }
        impl PartialEq for Entry {
            fn eq(&self, o: &Self) -> bool {
                self.sort_key == o.sort_key
            }
        }
        impl Eq for Entry {}
        impl Ord for Entry {
            fn cmp(&self, o: &Self) -> std::cmp::Ordering {
                self.sort_key.cmp(&o.sort_key)
            }
        }
        impl PartialOrd for Entry {
            fn partial_cmp(&self, o: &Self) -> Option<std::cmp::Ordering> {
                Some(self.cmp(o))
            }
        }

        let mut heap: std::collections::BinaryHeap<Entry> =
            std::collections::BinaryHeap::with_capacity(cap + 1);
        let mut present: std::collections::HashSet<String> = std::collections::HashSet::new();

        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            let Some(hex_key) = name.strip_suffix(".meta") else { continue };
            // Hex-decode filename back to the original key bytes.
            let Ok(key_bytes) = hex_decode(hex_key) else { continue };
            let Ok(key) = String::from_utf8(key_bytes) else { continue };
            if !key.starts_with(prefix) {
                continue;
            }

            // Fold to a folder when a delimiter occurs in the remainder after `prefix`.
            let (sort_key, is_prefix) = match delimiter {
                Some(d) if !d.is_empty() => match key[prefix.len()..].find(d) {
                    Some(i) => (key[..prefix.len() + i + d.len()].to_string(), true),
                    None => (key, false),
                },
                _ => (key, false),
            };

            // Resume strictly AFTER the previous page's last entry, compared at the
            // ENTRY level: a folder already emitted on a prior page is skipped even
            // though its member keys sort lexicographically after the folder marker.
            if start_after.is_some_and(|sa| sort_key.as_str() <= sa) {
                continue;
            }
            if present.contains(&sort_key) {
                continue; // a folder already represented by an earlier member key
            }
            if heap.len() < cap {
                present.insert(sort_key.clone());
                heap.push(Entry { sort_key, is_prefix });
            } else if sort_key.as_str() < heap.peek().unwrap().sort_key.as_str() {
                // Evict the current largest to make room for this smaller distinct entry.
                let popped = heap.pop().unwrap();
                present.remove(&popped.sort_key);
                present.insert(sort_key.clone());
                heap.push(Entry { sort_key, is_prefix });
            }
        }

        // Ascending page; truncated iff a `cap`-th (overflow) entry was retained.
        let mut entries = heap.into_sorted_vec();
        let is_truncated = entries.len() > max_keys;
        if is_truncated {
            entries.truncate(max_keys);
        }
        let next_continuation_token = if is_truncated {
            entries.last().map(|e| e.sort_key.clone())
        } else {
            None
        };

        // Read metadata only for the page's object keys (folders carry no meta).
        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();
        for e in entries {
            if e.is_prefix {
                common_prefixes.push(e.sort_key);
                continue;
            }
            let hk = hex(e.sort_key.as_bytes());
            let meta_path = dir.join(format!("{hk}.meta"));
            let bytes = match tokio::fs::read(&meta_path).await {
                Ok(b) => b,
                Err(err) if err.kind() == std::io::ErrorKind::NotFound => continue, // raced with delete
                Err(err) => return Err(err.into()),
            };
            let meta: ObjectMeta = serde_json::from_slice(&bytes)
                .map_err(|_| ObjectError::CorruptMeta(e.sort_key.clone()))?;
            objects.push(meta);
        }

        Ok(ListV2Page { objects, common_prefixes, is_truncated, next_continuation_token })
    }

    // ---- multipart upload -------------------------------------------------

    /// Initiate a multipart upload; returns the opaque upload id.
    pub async fn create_multipart(&self, bucket: &str, key: &str, content_type: &str) -> Result<String> {
        validate_key(key)?;
        let dir = self.require_bucket(bucket).await?;
        let upload_id = new_upload_id();
        let sdir = dir.join(".uploads").join(&upload_id);
        tokio::fs::create_dir_all(&sdir).await?;
        let info = UploadInfo {
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: now_secs(),
        };
        tokio::fs::write(sdir.join("info.json"), serde_json::to_vec(&info).unwrap()).await?;
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
        self.upload_part_capped(bucket, upload_id, part_number, reader, expected_sha256, None)
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
            return Err(ObjectError::InvalidArgument(format!("part number {part_number}")));
        }
        let sdir = self.staging(bucket, upload_id).await?;
        let part = sdir.join(format!("part-{part_number}"));
        let tmp = sdir.join(format!("part-{part_number}.tmp"));

        let result = write_stream(&tmp, &mut reader, expected_sha256, declared_len).await;
        match result {
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e)
            }
            Ok((_, _, raw_md5)) => {
                if let Err(e) = tokio::fs::rename(&tmp, &part).await {
                    let _ = tokio::fs::remove_file(&tmp).await;
                    return Err(e.into());
                }
                // Persist the raw 16-byte digest; the final multipart etag is md5-of-md5s.
                tokio::fs::write(sdir.join(format!("part-{part_number}.md5")), &raw_md5).await?;
                Ok(hex(&raw_md5))
            }
        }
    }

    /// Complete a multipart upload: concatenate `part_numbers` in order into the
    /// final object, returning its metadata with the S3 multipart etag
    /// `md5(concat of the part md5s)-<count>`.
    pub async fn complete_multipart(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_numbers: &[u32],
    ) -> Result<ObjectMeta> {
        validate_key(key)?;
        let sdir = self.staging(bucket, upload_id).await?;
        let info: UploadInfo =
            serde_json::from_slice(&tokio::fs::read(sdir.join("info.json")).await?)
                .map_err(|_| ObjectError::CorruptMeta(upload_id.to_string()))?;
        if info.key != key {
            return Err(ObjectError::InvalidArgument("key does not match upload".into()));
        }
        if part_numbers.is_empty() {
            return Err(ObjectError::InvalidArgument("no parts".into()));
        }
        // Re-validate the bucket here too (every other write path goes through
        // require_bucket); staging() already did, but don't rely on call-order.
        let dir = self.require_bucket(bucket).await?;
        let hk = hex(key.as_bytes());
        let obj = dir.join(&hk);
        let tmp = dir.join(format!(
            "{hk}.cmpl.{}.{}",
            std::process::id(),
            TMP_SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let mut concat = Md5::new();
        let mut size = 0u64;
        {
            let mut out = tokio::fs::File::create(&tmp).await?;
            for &pn in part_numbers {
                let mut pf = match tokio::fs::File::open(sdir.join(format!("part-{pn}"))).await {
                    Ok(f) => f,
                    Err(_) => {
                        let _ = tokio::fs::remove_file(&tmp).await;
                        return Err(ObjectError::InvalidArgument(format!("missing part {pn}")));
                    }
                };
                size += tokio::io::copy(&mut pf, &mut out).await?;
                concat.update(&tokio::fs::read(sdir.join(format!("part-{pn}.md5"))).await?);
            }
            out.sync_all().await?;
        }
        tokio::fs::rename(&tmp, &obj).await?;
        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: format!("{}-{}", hex(&concat.finalize()), part_numbers.len()),
            content_type: info.content_type,
            last_modified: now_secs(),
        };
        let meta_path = dir.join(format!("{hk}.meta"));
        if let Err(e) = tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).await {
            // Drop the orphaned bytes; leave staging intact so the client can retry.
            let _ = tokio::fs::remove_file(&obj).await;
            let _ = tokio::fs::remove_file(&meta_path).await;
            return Err(e.into());
        }
        let _ = tokio::fs::remove_dir_all(&sdir).await;
        if let Some(p) = sdir.parent() {
            let _ = tokio::fs::remove_dir(p).await; // drop .uploads if now empty
        }
        Ok(meta)
    }

    /// Abort a multipart upload, discarding its staged parts.
    pub async fn abort_multipart(&self, bucket: &str, upload_id: &str) -> Result<()> {
        let sdir = self.staging(bucket, upload_id).await?;
        let _ = tokio::fs::remove_dir_all(&sdir).await;
        if let Some(p) = sdir.parent() {
            let _ = tokio::fs::remove_dir(p).await; // drop .uploads if now empty
        }
        Ok(())
    }

    /// List all pending multipart uploads in `bucket`.
    pub async fn list_multipart_uploads(&self, bucket: &str) -> Result<Vec<MultipartUpload>> {
        let dir = self.require_bucket(bucket).await?;
        let uploads_dir = dir.join(".uploads");
        let mut out = Vec::new();
        let mut rd = match tokio::fs::read_dir(&uploads_dir).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(out),
            Err(e) => return Err(e.into()),
        };
        while let Some(entry) = rd.next_entry().await? {
            if !entry.file_type().await?.is_dir() {
                continue;
            }
            let upload_id = entry.file_name().to_string_lossy().into_owned();
            let info_path = entry.path().join("info.json");
            let bytes = match tokio::fs::read(&info_path).await {
                Ok(b) => b,
                Err(_) => continue, // partially created or already removed
            };
            let info: UploadInfo = match serde_json::from_slice(&bytes) {
                Ok(i) => i,
                Err(_) => continue,
            };
            out.push(MultipartUpload {
                upload_id,
                key: info.key,
                initiated: info.initiated,
            });
        }
        out.sort_by(|a, b| a.upload_id.cmp(&b.upload_id));
        Ok(out)
    }

    /// Remove abandoned uploads across ALL buckets whose `info.json` mtime (or
    /// `initiated` field) is older than `max_age`. Returns the number of upload
    /// directories removed. Also removes empty `.uploads` parent dirs.
    pub async fn sweep_stale_uploads(&self, max_age: Duration) -> Result<usize> {
        let threshold = now_secs().saturating_sub(max_age.as_secs());
        let mut removed = 0usize;

        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        while let Some(bucket_entry) = rd.next_entry().await? {
            let name = bucket_entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !bucket_entry.file_type().await?.is_dir() {
                continue;
            }
            let uploads_dir = bucket_entry.path().join(".uploads");
            let mut urd = match tokio::fs::read_dir(&uploads_dir).await {
                Ok(rd) => rd,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
                Err(e) => return Err(e.into()),
            };
            while let Some(uid_entry) = urd.next_entry().await? {
                if !uid_entry.file_type().await?.is_dir() {
                    continue;
                }
                let info_path = uid_entry.path().join("info.json");
                // Use the `initiated` field if present, fall back to file mtime.
                let age_secs = if let Ok(bytes) = tokio::fs::read(&info_path).await {
                    if let Ok(info) = serde_json::from_slice::<UploadInfo>(&bytes) {
                        if info.initiated > 0 {
                            info.initiated
                        } else {
                            mtime_secs(&info_path).await.unwrap_or(0)
                        }
                    } else {
                        mtime_secs(&info_path).await.unwrap_or(0)
                    }
                } else {
                    mtime_secs(&uid_entry.path()).await.unwrap_or(0)
                };
                if age_secs <= threshold {
                    let _ = tokio::fs::remove_dir_all(uid_entry.path()).await;
                    removed += 1;
                }
            }
            // Clean up empty .uploads dir.
            let _ = tokio::fs::remove_dir(&uploads_dir).await;
        }
        Ok(removed)
    }

    /// Count `(buckets, objects)` for this store in a single pass — buckets are the
    /// non-dot top-level dirs, objects are the `.meta` sidecars within them. Used by
    /// the server's per-project count quota (cached on a TTL, never per request).
    pub async fn usage_counts(&self) -> Result<(u64, u64)> {
        let mut buckets = 0u64;
        let mut objects = 0u64;
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok((0, 0)),
            Err(e) => return Err(e.into()),
        };
        while let Some(bucket_entry) = rd.next_entry().await? {
            let name = bucket_entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !bucket_entry.file_type().await?.is_dir() {
                continue;
            }
            buckets += 1;
            let mut brd = match tokio::fs::read_dir(bucket_entry.path()).await {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            while let Some(obj) = brd.next_entry().await? {
                if obj.file_name().to_string_lossy().ends_with(".meta") {
                    objects += 1;
                }
            }
        }
        Ok((buckets, objects))
    }

    /// Total in-flight multipart uploads across all buckets (`.uploads/*` dirs).
    /// Counting stops once `cap` is reached so the initiate gate stays O(cap), not
    /// O(all staged uploads). Returns `min(actual, cap)`.
    pub async fn count_inflight_uploads(&self, cap: u64) -> Result<u64> {
        let mut total = 0u64;
        let mut rd = match tokio::fs::read_dir(&self.root).await {
            Ok(rd) => rd,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(e) => return Err(e.into()),
        };
        while let Some(bucket_entry) = rd.next_entry().await? {
            let name = bucket_entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !bucket_entry.file_type().await?.is_dir() {
                continue;
            }
            let mut urd = match tokio::fs::read_dir(bucket_entry.path().join(".uploads")).await {
                Ok(rd) => rd,
                Err(_) => continue,
            };
            while let Some(u) = urd.next_entry().await? {
                if u.file_type().await?.is_dir() {
                    total += 1;
                    if total >= cap {
                        return Ok(total);
                    }
                }
            }
        }
        Ok(total)
    }

    async fn staging(&self, bucket: &str, upload_id: &str) -> Result<PathBuf> {
        let dir = self.require_bucket(bucket).await?;
        validate_upload_id(upload_id)?;
        let sdir = dir.join(".uploads").join(upload_id);
        if !tokio::fs::try_exists(&sdir).await? {
            return Err(ObjectError::NoSuchUpload(upload_id.to_string()));
        }
        Ok(sdir)
    }

    async fn locate(&self, bucket: &str, key: &str) -> Result<(ObjectMeta, PathBuf)> {
        let dir = self.require_bucket(bucket).await?;
        validate_key(key)?;
        let hk = hex(key.as_bytes());
        let obj = dir.join(&hk);
        let meta_path = dir.join(format!("{hk}.meta"));
        let bytes = match tokio::fs::read(&meta_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ObjectError::NoSuchKey(key.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let meta: ObjectMeta =
            serde_json::from_slice(&bytes).map_err(|_| ObjectError::CorruptMeta(key.to_string()))?;
        Ok((meta, obj))
    }
}

/// Shared write-loop for `put_object` and `upload_part`. Streams `reader` into
/// `tmp`, enforcing per-read idle timeout and total-upload cap. Computes MD5
/// (for etag) and SHA-256 (for content binding) simultaneously.
///
/// Returns `(size, hex_md5_etag, raw_md5_bytes)` on success.
/// The caller is responsible for unlinking `tmp` on any `Err` return.
async fn write_stream<R: AsyncRead + Unpin>(
    tmp: &PathBuf,
    reader: &mut R,
    expected_sha256: Option<&str>,
    declared_len: Option<u64>,
) -> Result<(u64, String, Vec<u8>)> {
    let mut md5_hasher: Md5 = Md5::new();
    let mut sha_hasher: Sha256 = Sha256::new();
    let mut size = 0u64;
    let deadline = Instant::now() + upload_deadline(declared_len);

    let mut f = tokio::fs::File::create(tmp).await?;
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
        f.write_all(&buf[..n]).await?;
        size += n as u64;
    }
    f.sync_all().await?;

    let raw_md5 = md5_hasher.finalize().to_vec();
    let etag = hex(&raw_md5);

    if let Some(exp) = expected_sha256 {
        let actual = hex(&sha_hasher.finalize());
        if actual != exp.to_lowercase() {
            return Err(ObjectError::ContentSha256Mismatch);
        }
    }

    Ok((size, etag, raw_md5))
}

async fn mtime_secs(path: &std::path::Path) -> Option<u64> {
    let meta = tokio::fs::metadata(path).await.ok()?;
    meta.modified().ok()?.duration_since(UNIX_EPOCH).ok().map(|d| d.as_secs())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        s.push(char::from_digit((b >> 4) as u32, 16).unwrap());
        s.push(char::from_digit((b & 0xf) as u32, 16).unwrap());
    }
    s
}

/// Decode a lowercase-hex string to bytes. Returns `Err(())` if the input is
/// not valid even-length hex (filenames are always valid since we write them,
/// but malformed entries are silently skipped in listings).
fn hex_decode(s: &str) -> std::result::Result<Vec<u8>, ()> {
    if !s.len().is_multiple_of(2) {
        return Err(());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    let mut i = 0;
    while i < b.len() {
        let hi = hex_digit(b[i])?;
        let lo = hex_digit(b[i + 1])?;
        out.push((hi << 4) | lo);
        i += 2;
    }
    Ok(out)
}

fn hex_digit(b: u8) -> std::result::Result<u8, ()> {
    match b {
        b'0'..=b'9' => Ok(b - b'0'),
        b'a'..=b'f' => Ok(b - b'a' + 10),
        b'A'..=b'F' => Ok(b - b'A' + 10),
        _ => Err(()),
    }
}

/// Opaque, traversal-safe (pure hex) upload id.
fn new_upload_id() -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!(
        "{nanos:032x}{:08x}{:08x}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

fn validate_upload_id(id: &str) -> Result<()> {
    if !id.is_empty() && id.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err(ObjectError::InvalidArgument(format!("invalid upload id {id:?}")))
    }
}

/// S3 bucket naming (simplified): 3–63 chars, lowercase letters/digits/hyphen, not
/// starting or ending with a hyphen.
fn validate_bucket(bucket: &str) -> Result<()> {
    let ok = (3..=63).contains(&bucket.len())
        && bucket.bytes().all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !bucket.starts_with('-')
        && !bucket.ends_with('-');
    if ok {
        Ok(())
    } else {
        Err(ObjectError::InvalidBucketName(bucket.to_string()))
    }
}

/// Object keys: 1–1024 bytes, UTF-8 (guaranteed by `&str`), no NUL. The flat
/// keyspace (incl. `/`) is preserved because keys are hex-encoded for storage.
fn validate_key(key: &str) -> Result<()> {
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

    async fn read_all(mut f: tokio::fs::File) -> Vec<u8> {
        let mut v = Vec::new();
        f.read_to_end(&mut v).await.unwrap();
        v
    }

    #[tokio::test]
    async fn put_get_head_delete_round_trip() {
        let dir = root("rt");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("my-bucket").await.unwrap();
        let body = b"hello object store";
        let meta = s.put_object("my-bucket", "a/b/c.txt", &body[..], "text/plain", None).await.unwrap();
        assert_eq!(meta.size, body.len() as u64);
        // S3 etag = hex md5 of the bytes.
        assert_eq!(meta.etag, format!("{:x}", Md5::digest(body)));

        let (m2, f) = s.get_object("my-bucket", "a/b/c.txt").await.unwrap();
        assert_eq!(m2, meta);
        assert_eq!(read_all(f).await, body);
        assert_eq!(s.head_object("my-bucket", "a/b/c.txt").await.unwrap().content_type, "text/plain");

        s.delete_object("my-bucket", "a/b/c.txt").await.unwrap();
        assert!(matches!(s.head_object("my-bucket", "a/b/c.txt").await, Err(ObjectError::NoSuchKey(_))));
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
        s.put_object("flatbucket", "a/b", &b"1"[..], "x", None).await.unwrap();
        s.put_object("flatbucket", "a/b/c", &b"2"[..], "x", None).await.unwrap();
        assert_eq!(read_all(s.get_object("flatbucket", "a/b").await.unwrap().1).await, b"1");
        assert_eq!(read_all(s.get_object("flatbucket", "a/b/c").await.unwrap().1).await, b"2");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn list_is_prefix_filtered_and_bucket_isolated() {
        let dir = root("list");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bucket-one").await.unwrap();
        s.create_bucket("bucket-two").await.unwrap();
        s.put_object("bucket-one", "img/a", &b"x"[..], "x", None).await.unwrap();
        s.put_object("bucket-one", "img/b", &b"x"[..], "x", None).await.unwrap();
        s.put_object("bucket-one", "doc/c", &b"x"[..], "x", None).await.unwrap();
        s.put_object("bucket-two", "img/z", &b"x"[..], "x", None).await.unwrap();

        let page = s.list_objects("bucket-one", "img/", None, 1000).await.unwrap();
        let keys: Vec<_> = page.objects.into_iter().map(|m| m.key).collect();
        assert_eq!(keys, vec!["img/a".to_string(), "img/b".to_string()]);
        // Isolation: b2's object never shows up under b1.
        assert_eq!(s.list_objects("bucket-two", "", None, 1000).await.unwrap().objects.len(), 1);
    }

    #[tokio::test]
    async fn list_pagination() {
        let dir = root("page");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("page-bucket").await.unwrap();
        for i in 0..5u32 {
            s.put_object("page-bucket", &format!("k{i}"), &b"x"[..], "x", None).await.unwrap();
        }
        let p1 = s.list_objects("page-bucket", "", None, 3).await.unwrap();
        assert_eq!(p1.objects.len(), 3);
        assert!(p1.is_truncated);
        let token = p1.next_continuation_token.unwrap();
        assert_eq!(token, "k2");

        let p2 = s.list_objects("page-bucket", "", Some(&token), 3).await.unwrap();
        assert_eq!(p2.objects.len(), 2);
        assert!(!p2.is_truncated);
        assert!(p2.next_continuation_token.is_none());

        let all_keys: Vec<_> = p1.objects.iter().chain(p2.objects.iter()).map(|m| m.key.clone()).collect();
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
        assert_eq!(page.common_prefixes, vec!["a/".to_string(), "b/".to_string()]);
        assert!(!page.is_truncated);

        // Descend into folder "a/": its members become the objects, no sub-folders.
        let sub = s.list_v2("buk", "a/", Some("/"), None, 1000).await.unwrap();
        let sub_objs: Vec<_> = sub.objects.iter().map(|m| m.key.clone()).collect();
        assert_eq!(sub_objs, vec!["a/1".to_string(), "a/2".to_string(), "a/3".to_string()]);
        assert!(sub.common_prefixes.is_empty());

        // Nested folders one level down are folded, not flattened.
        s.put_object("buk", "a/deep/z", &b"x"[..], "x", None).await.unwrap();
        let sub2 = s.list_v2("buk", "a/", Some("/"), None, 1000).await.unwrap();
        assert_eq!(sub2.common_prefixes, vec!["a/deep/".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn upload_deadline_is_size_aware_with_a_floor() {
        // Unknown / small uploads get the floor; a large declared length scales the
        // budget so a near-quota single PUT over a slow link isn't capped at the floor.
        assert_eq!(upload_deadline(None), MIN_UPLOAD_DEADLINE);
        assert_eq!(upload_deadline(Some(1024)), MIN_UPLOAD_DEADLINE); // tiny -> floor
        assert_eq!(upload_deadline(Some(0)), MIN_UPLOAD_DEADLINE);
        // 16 GiB at the 1 MiB/s floor rate = 16384s, well above the 3600s floor.
        let huge = 16u64 * 1024 * 1024 * 1024;
        assert_eq!(upload_deadline(Some(huge)), Duration::from_secs(huge / MIN_UPLOAD_RATE));
        assert!(upload_deadline(Some(huge)) > MIN_UPLOAD_DEADLINE);
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
        s.put_object("buk", "dir/", &b""[..], "x", None).await.unwrap();
        s.put_object("buk", "dir/file", &b"x"[..], "x", None).await.unwrap();

        let root_page = s.list_v2("buk", "", Some("/"), None, 1000).await.unwrap();
        assert!(root_page.objects.is_empty(), "marker must not list as a root object");
        assert_eq!(root_page.common_prefixes, vec!["dir/".to_string()]);

        // Inside the folder, the marker object (remainder "" has no delimiter) appears.
        let sub = s.list_v2("buk", "dir/", Some("/"), None, 1000).await.unwrap();
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
        let p2 = s.list_v2("buk", "", Some("/"), Some(&token), 2).await.unwrap();
        assert_eq!(p2.common_prefixes, vec!["d/".to_string()]);
        assert_eq!(p2.objects.iter().map(|m| m.key.clone()).collect::<Vec<_>>(), vec!["c.txt".to_string()]);
        assert!(!p2.is_truncated);
        assert!(p2.next_continuation_token.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn errors_for_missing_bucket_and_invalid_names() {
        let dir = root("err");
        let s = ObjectStore::open(&dir).unwrap();
        assert!(matches!(s.put_object("nope", "k", &b""[..], "x", None).await, Err(ObjectError::NoSuchBucket(_))));
        assert!(matches!(s.create_bucket("AB").await, Err(ObjectError::InvalidBucketName(_)))); // too short + uppercase
        s.create_bucket("ok-bucket").await.unwrap();
        assert!(matches!(s.create_bucket("ok-bucket").await, Err(ObjectError::BucketAlreadyExists(_))));
        s.put_object("ok-bucket", "k", &b"x"[..], "x", None).await.unwrap();
        assert!(matches!(s.delete_bucket("ok-bucket").await, Err(ObjectError::BucketNotEmpty(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_concatenates_parts_in_order() {
        let dir = root("mpu");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("mp-bucket").await.unwrap();
        let uid = s.create_multipart("mp-bucket", "big/file", "application/octet-stream").await.unwrap();
        let e1 = s.upload_part("mp-bucket", &uid, 1, &b"hello "[..], None).await.unwrap();
        let e2 = s.upload_part("mp-bucket", &uid, 2, &b"world"[..], None).await.unwrap();
        assert_eq!(e1, format!("{:x}", Md5::digest(b"hello ")));
        assert_eq!(e2, format!("{:x}", Md5::digest(b"world")));

        let meta = s.complete_multipart("mp-bucket", "big/file", &uid, &[1, 2]).await.unwrap();
        assert_eq!(meta.size, 11);
        assert!(meta.etag.ends_with("-2")); // S3 multipart etag carries the part count
        assert_eq!(read_all(s.get_object("mp-bucket", "big/file").await.unwrap().1).await, b"hello world");

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
        let uid = s.create_multipart("ab-bucket", "k", "x").await.unwrap();
        s.upload_part("ab-bucket", &uid, 1, &b"data"[..], None).await.unwrap();
        s.abort_multipart("ab-bucket", &uid).await.unwrap();
        assert!(matches!(
            s.complete_multipart("ab-bucket", "k", &uid, &[1]).await,
            Err(ObjectError::NoSuchUpload(_))
        ));
        assert!(matches!(s.head_object("ab-bucket", "k").await, Err(ObjectError::NoSuchKey(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_list_and_sweep() {
        let dir = root("mpu-list");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("sweep-bucket").await.unwrap();
        let uid = s.create_multipart("sweep-bucket", "pending/obj", "application/octet-stream").await.unwrap();
        s.upload_part("sweep-bucket", &uid, 1, &b"part"[..], None).await.unwrap();

        let uploads = s.list_multipart_uploads("sweep-bucket").await.unwrap();
        assert_eq!(uploads.len(), 1);
        assert_eq!(uploads[0].upload_id, uid);
        assert_eq!(uploads[0].key, "pending/obj");

        // Zero seconds max_age -> everything is "stale" (initiated <= now - 0 = now).
        // Use 1s so freshly created upload IS stale only when initiated < now.
        // Force stale by using a tiny threshold: max_age = u64::MAX seconds.
        let removed = s.sweep_stale_uploads(Duration::from_secs(u64::MAX / 2)).await.unwrap();
        // Not stale (just created) — no removal.
        assert_eq!(removed, 0);

        // With max_age=0 every upload is stale.
        let removed = s.sweep_stale_uploads(Duration::from_secs(0)).await.unwrap();
        assert_eq!(removed, 1);
        assert_eq!(s.list_multipart_uploads("sweep-bucket").await.unwrap().len(), 0);

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
        s.put_object("sha-bucket", "k", &body[..], "x", Some(&correct)).await.unwrap();
        // Wrong hash -> ContentSha256Mismatch.
        assert!(matches!(
            s.put_object("sha-bucket", "k", &body[..], "x", Some("aaaa")).await,
            Err(ObjectError::ContentSha256Mismatch)
        ));
        // None -> no check.
        s.put_object("sha-bucket", "k", &body[..], "x", None).await.unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }
}
