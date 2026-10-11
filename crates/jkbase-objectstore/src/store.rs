use crate::cors::CorsConfig;
use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

/// Longest single file name the bucket's filesystem accepts (ext4 / xfs / btrfs).
const NAME_MAX: usize = 255;
const META_SUFFIX: &str = ".meta";

/// Keys up to this many bytes are stored under `hex(key)`: the longest whose sidecar
/// name (`2n` hex chars + `.meta`) still fits `NAME_MAX`. Every object written before
/// longer keys were storable is in this range (the old temp-file name capped keys at
/// 123 bytes at most), so it is read back with no migration.
const HEX_NAME_MAX_KEY: usize = (NAME_MAX - META_SUFFIX.len()) / 2;

/// Name prefix of a key stored whole in base64 ([`b64`]): `b-<b64(key)>`. Fits keys up
/// to [`B64_NAME_MAX_KEY`] bytes.
const B64_NAME_PREFIX: &str = "b-";
const B64_NAME_MAX_KEY: usize = 186; // 2 + ceil(186·4/3) + ".meta" = 255

/// Name prefix of a key too long for any whole-key name: `k-<b64(sha256(key))>.<b64(head)>`,
/// 43 + 204 base64 chars — 255 bytes with `.meta`. Neither prefix is valid hex (`-`), so
/// the three name spaces are disjoint and a `hex(key)`-only reader skips the new ones.
const HASH_NAME_PREFIX: &str = "k-";
const HASH_NAME_DIGEST_CHARS: usize = 43;

/// Leading key bytes embedded in a hashed name. Listing uses this head to filter by
/// prefix, fold folders and paginate WITHOUT opening the sidecar of every such object.
const HASH_NAME_HEAD: usize = 153; // ceil(153·4/3) = 204

/// The on-disk file-name stem for `key` (the bytes live at `<stem>`, the JSON sidecar
/// at `<stem>.meta`). Pure function of the key; traversal-safe (no `/`, no `.` first).
///
/// - `<= 125` bytes: `hex(key)` — the original scheme.
/// - `<= 186` bytes: `b-<b64(key)>` — hex would exceed `NAME_MAX`; base64 still holds
///   the whole key, so the name alone identifies it (no sidecar read to list).
/// - up to the 1024-byte S3 limit: `k-<b64(sha256(key))>.<b64(first 153 bytes)>`. The
///   full key is in the sidecar; the hash keeps keys that share a head in distinct files.
fn object_stem(key: &str) -> String {
    let b = key.as_bytes();
    if b.len() <= HEX_NAME_MAX_KEY {
        hex(b)
    } else if b.len() <= B64_NAME_MAX_KEY {
        format!("{B64_NAME_PREFIX}{}", b64(b))
    } else {
        format!(
            "{HASH_NAME_PREFIX}{}.{}",
            b64(&Sha256::digest(b)),
            b64(&b[..HASH_NAME_HEAD])
        )
    }
}

/// What a listing learns about an object from its file-name stem alone.
enum StemKey {
    /// A whole-key name (`hex` or `b-`): the key.
    Exact(String),
    /// A hashed name: only the key's first [`HASH_NAME_HEAD`] bytes (the rest is in the
    /// sidecar). May end mid-way through a multi-byte character.
    Head(Vec<u8>),
}

/// Parse a stem written by [`object_stem`]; `None` for anything else (skipped). A name
/// only counts in the tier `object_stem` would have chosen for its key, so every object
/// has exactly one name.
fn parse_stem(stem: &str) -> Option<StemKey> {
    if let Some(rest) = stem.strip_prefix(HASH_NAME_PREFIX) {
        let (digest, head) = rest.split_at_checked(HASH_NAME_DIGEST_CHARS)?;
        let head = b64_decode(head.strip_prefix('.')?)?;
        b64_decode(digest)?;
        return (head.len() == HASH_NAME_HEAD).then_some(StemKey::Head(head));
    }
    let key = match stem.strip_prefix(B64_NAME_PREFIX) {
        Some(rest) => b64_decode(rest)?,
        None => hex_decode(stem).ok()?,
    };
    let key = String::from_utf8(key).ok()?;
    // Wrong tier for its length, or uppercase hex: not a name this store writes.
    (object_stem(&key) == stem).then_some(StemKey::Exact(key))
}

/// What a hashed name's head alone settles for a listing under `prefix` / `delimiter`.
enum HeadVerdict {
    /// The key cannot match `prefix`.
    Skip,
    /// The key folds into this common prefix (the delimiter occurs inside the head).
    Folder(String),
    /// Matches as far as the head goes; the full key (sidecar) decides the rest.
    NeedKey,
}

fn judge_head(head: &[u8], prefix: &str, delimiter: Option<&str>) -> HeadVerdict {
    let p = prefix.as_bytes();
    if p.len() > head.len() {
        // The prefix reaches past the head: the head can only rule the key out.
        return if p.starts_with(head) {
            HeadVerdict::NeedKey
        } else {
            HeadVerdict::Skip
        };
    }
    if !head.starts_with(p) {
        return HeadVerdict::Skip;
    }
    if let Some(d) = delimiter.filter(|d| !d.is_empty()) {
        let d = d.as_bytes();
        // The first occurrence inside the head is the first in the key. UTF-8 is
        // self-synchronizing, so the cut after a whole delimiter is a char boundary.
        if let Some(i) = head[p.len()..].windows(d.len()).position(|w| w == d)
            && let Ok(folder) = String::from_utf8(head[..p.len() + i + d.len()].to_vec())
        {
            return HeadVerdict::Folder(folder);
        }
    }
    HeadVerdict::NeedKey
}

/// Concurrent listings of one store (one project). A listing scans the whole bucket
/// directory, and hashed-name objects sharing a head cost a sidecar read each, so a
/// tenant could otherwise multiply that host I/O by issuing LISTs in parallel. Extra
/// requests wait their turn; they are not refused.
const MAX_CONCURRENT_LISTS: usize = 4;

/// A key starting with `head` is certainly `<= start_after` (so a resumed listing has
/// already passed it): `head` sorts strictly before `start_after` at a byte both have.
fn head_precedes(head: &[u8], start_after: &str) -> bool {
    let sa = start_after.as_bytes();
    let n = head.len().min(sa.len());
    head[..n] < sa[..n]
}

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
/// floor rate (~4.6h); larger objects must use multipart.
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
struct UploadInfo {
    key: String,
    content_type: String,
    /// Unix seconds at which the upload was initiated. Defaulted to 0 for
    /// uploads created before this field existed (pre-hardening).
    #[serde(default)]
    initiated: u64,
    /// `Cache-Control` captured at initiate, applied to the completed object.
    #[serde(default)]
    cache_control: Option<String>,
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
    /// Client-supplied `Cache-Control` to echo on GET/HEAD. `#[serde(default)]` so
    /// sidecars written before this field existed still deserialize (as `None`).
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

/// A tenant object store rooted at `root`, one subdirectory per bucket. Each
/// object is two files: `<stem>` (the bytes) and `<stem>.meta` (JSON), where the stem
/// is [`object_stem`] of its key.
pub struct ObjectStore {
    root: PathBuf,
    list_permits: tokio::sync::Semaphore,
}

impl ObjectStore {
    /// Open (creating if absent) an object store rooted at `root`.
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        std::fs::create_dir_all(&root)?;
        Ok(Self {
            root,
            list_permits: tokio::sync::Semaphore::new(MAX_CONCURRENT_LISTS),
        })
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
        // Drop any CORS sidecar (it lives outside the bucket dir, so it didn't count
        // toward the emptiness check above) so a re-created same-name bucket starts clean.
        let _ = self.delete_bucket_cors(bucket).await;
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

    // ---- per-bucket CORS config -------------------------------------------
    //
    // Stored OUTSIDE the bucket dir at `{root}/.cors/{bucket}.json` on purpose: an
    // in-bucket sidecar would make an otherwise-empty bucket fail `delete_bucket`'s
    // emptiness check (same latent trap as `.uploads`), and `.cors` is dot-prefixed
    // so `list_buckets` already skips it. `validate_bucket` keeps the `{bucket}.json`
    // filename to `[a-z0-9-]` — no traversal.

    fn cors_path(&self, bucket: &str) -> PathBuf {
        self.root.join(".cors").join(format!("{bucket}.json"))
    }

    /// Store the bucket's CORS config (bucket must exist).
    pub async fn put_bucket_cors(&self, bucket: &str, cfg: &CorsConfig) -> Result<()> {
        self.require_bucket(bucket).await?;
        let path = self.cors_path(bucket);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await?;
        }
        tokio::fs::write(&path, serde_json::to_vec(cfg).unwrap()).await?;
        Ok(())
    }

    /// The bucket's CORS config, or `None` if unset. A corrupt sidecar reads as
    /// `None` (fail-open to "no CORS"): it governs only the tenant's own bucket, so
    /// the worst case is their browser client loses access, never a cross-tenant leak.
    pub async fn get_bucket_cors(&self, bucket: &str) -> Result<Option<CorsConfig>> {
        validate_bucket(bucket)?;
        match tokio::fs::read(self.cors_path(bucket)).await {
            Ok(bytes) => Ok(serde_json::from_slice(&bytes).ok()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    /// Remove the bucket's CORS config (idempotent).
    pub async fn delete_bucket_cors(&self, bucket: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let _ = tokio::fs::remove_file(self.cors_path(bucket)).await;
        Ok(())
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
        self.put_object_capped(bucket, key, reader, content_type, None, expected_sha256, None)
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
        let dir = self.require_bucket(bucket).await?;
        let hk = object_stem(key);
        let obj = dir.join(&hk);
        let tmp = dir.join(tmp_name("tmp"));

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
                    cache_control: cache_control.map(str::to_string),
                };
                let meta_path = dir.join(format!("{hk}.meta"));
                if let Err(e) =
                    tokio::fs::write(&meta_path, serde_json::to_vec(&meta).unwrap()).await
                {
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
    pub async fn get_object(
        &self,
        bucket: &str,
        key: &str,
    ) -> Result<(ObjectMeta, tokio::fs::File)> {
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
        let hk = object_stem(key);
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
        // Never closed, so this only ever waits.
        let _scan = self.list_permits.acquire().await;

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
            let Some(stem) = name.strip_suffix(META_SUFFIX) else {
                continue;
            };
            // The key comes from the name alone wherever it can: a whole-key name is
            // the key, and a hashed name's head usually settles the entry (wrong prefix,
            // a folder, already listed, or past this page). Only a hashed-name key still
            // in contention for the page costs a sidecar read.
            let mut folded = None;
            let key = match parse_stem(stem) {
                None => continue,
                Some(StemKey::Exact(key)) => key,
                Some(StemKey::Head(head)) => match judge_head(&head, prefix, delimiter) {
                    HeadVerdict::Skip => continue,
                    HeadVerdict::Folder(folder) => {
                        folded = Some(folder);
                        String::new()
                    }
                    HeadVerdict::NeedKey => {
                        if start_after.is_some_and(|sa| head_precedes(&head, sa)) {
                            continue;
                        }
                        // The key sorts at or after its head, so past a full page's
                        // largest entry it can't make the page.
                        if heap.len() == cap
                            && head.as_slice() > heap.peek().unwrap().sort_key.as_bytes()
                        {
                            continue;
                        }
                        let Ok(bytes) = tokio::fs::read(entry.path()).await else {
                            continue; // raced with a delete
                        };
                        match serde_json::from_slice::<ObjectMeta>(&bytes) {
                            // Only a sidecar sitting under its own key's name counts.
                            Ok(meta) if object_stem(&meta.key) == stem => meta.key,
                            _ => continue,
                        }
                    }
                },
            };

            // Fold to a folder when a delimiter occurs in the remainder after `prefix`.
            let (sort_key, is_prefix) = match (folded, delimiter) {
                (Some(folder), _) => (folder, true),
                (None, _) if !key.starts_with(prefix) => continue,
                (None, Some(d)) if !d.is_empty() => match key[prefix.len()..].find(d) {
                    Some(i) => (key[..prefix.len() + i + d.len()].to_string(), true),
                    None => (key, false),
                },
                (None, _) => (key, false),
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
                heap.push(Entry {
                    sort_key,
                    is_prefix,
                });
            } else if sort_key.as_str() < heap.peek().unwrap().sort_key.as_str() {
                // Evict the current largest to make room for this smaller distinct entry.
                let popped = heap.pop().unwrap();
                present.remove(&popped.sort_key);
                present.insert(sort_key.clone());
                heap.push(Entry {
                    sort_key,
                    is_prefix,
                });
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
            let hk = object_stem(&e.sort_key);
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

        Ok(ListV2Page {
            objects,
            common_prefixes,
            is_truncated,
            next_continuation_token,
        })
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
        let dir = self.require_bucket(bucket).await?;
        let upload_id = new_upload_id();
        let sdir = dir.join(".uploads").join(&upload_id);
        tokio::fs::create_dir_all(&sdir).await?;
        let info = UploadInfo {
            key: key.to_string(),
            content_type: content_type.to_string(),
            initiated: now_secs(),
            cache_control: cache_control.map(str::to_string),
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
            return Err(ObjectError::InvalidArgument(
                "key does not match upload".into(),
            ));
        }
        if part_numbers.is_empty() {
            return Err(ObjectError::InvalidArgument("no parts".into()));
        }
        // Re-validate the bucket here too (every other write path goes through
        // require_bucket); staging() already did, but don't rely on call-order.
        let dir = self.require_bucket(bucket).await?;
        let hk = object_stem(key);
        let obj = dir.join(&hk);
        let tmp = dir.join(tmp_name("cmpl"));
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
            cache_control: info.cache_control,
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
        let hk = object_stem(key);
        let obj = dir.join(&hk);
        let meta_path = dir.join(format!("{hk}.meta"));
        let bytes = match tokio::fs::read(&meta_path).await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                return Err(ObjectError::NoSuchKey(key.to_string()));
            }
            Err(e) => return Err(e.into()),
        };
        let meta: ObjectMeta = serde_json::from_slice(&bytes)
            .map_err(|_| ObjectError::CorruptMeta(key.to_string()))?;
        // A hashed name is not the key: never serve a sidecar that names a different one.
        if meta.key != key {
            return Err(ObjectError::NoSuchKey(key.to_string()));
        }
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
    meta.modified()
        .ok()?
        .duration_since(UNIX_EPOCH)
        .ok()
        .map(|d| d.as_secs())
}

fn now_secs() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// A bucket-dir scratch name for a body being written before its atomic rename into
/// place. Short and independent of the key (it used to be `<hex(key)>.tmp.<pid>.<seq>`,
/// which overflowed `NAME_MAX` for keys well under the hex-name limit — and sooner as
/// `<seq>` grew over the process's life). Never ends in `.meta`, so no scan counts it.
fn tmp_name(kind: &str) -> String {
    format!(
        ".{kind}.{}.{}",
        std::process::id(),
        TMP_SEQ.fetch_add(1, Ordering::Relaxed)
    )
}

/// Base64 over a file-name-safe alphabet in ASCII order (`-`, digits, upper, `_`,
/// lower), unpadded. Needs a case-sensitive filesystem (ext4 / xfs / btrfs are).
const B64_ALPHABET: &[u8; 64] = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

fn b64(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n = chunk
            .iter()
            .fold(0u32, |acc, &b| (acc << 8) | u32::from(b))
            << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            s.push(B64_ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    s
}

/// Inverse of [`b64`]; `None` unless `s` is exactly what `b64` writes for some bytes
/// (so a name maps to one key and back).
fn b64_decode(s: &str) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    for chunk in s.as_bytes().chunks(4) {
        let mut n = 0u32;
        for &c in chunk {
            n = (n << 6) | B64_ALPHABET.iter().position(|&a| a == c)? as u32;
        }
        n <<= 6 * (4 - chunk.len());
        let bytes = chunk.len().checked_sub(1).filter(|&b| b > 0)?;
        out.extend_from_slice(&n.to_be_bytes()[1..=bytes]);
    }
    (b64(&out) == s).then_some(out)
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
        Err(ObjectError::InvalidArgument(format!(
            "invalid upload id {id:?}"
        )))
    }
}

/// S3 bucket naming (simplified): 3–63 chars, lowercase letters/digits/hyphen, not
/// starting or ending with a hyphen.
fn validate_bucket(bucket: &str) -> Result<()> {
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

/// Object keys: 1–1024 bytes (the S3 limit), UTF-8 (guaranteed by `&str`), no NUL. The
/// flat keyspace (incl. `/`) is preserved because a key never becomes a path — see
/// [`object_stem`].
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
        let uid = s.create_multipart("ab-bucket", "k", "x", None).await.unwrap();
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
            .create_multipart("sweep-bucket", "pending/obj", "application/octet-stream", None)
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

    // ---- long keys (issue: PUT failed above ~116-byte keys) -------------------

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
        // Either side of every boundary: the old ~116–123 cap, the hex-name and
        // base64-name limits, the S3 limit.
        for n in [1, 116, 117, 123, 124, 125, 126, 127, 186, 187, 255, 512, 1024] {
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
            assert_eq!(s.head_object("bkt", &key).await.unwrap().size, body.len() as u64);
        }
        // Every file name stays inside the filesystem's limit, and nothing is left over.
        let mut names = Vec::new();
        for e in std::fs::read_dir(dir.join("bkt")).unwrap() {
            names.push(e.unwrap().file_name().to_string_lossy().into_owned());
        }
        assert!(names.iter().all(|n| n.len() <= NAME_MAX), "{names:?}");
        assert!(names.iter().all(|n| !n.starts_with('.')), "temp file left: {names:?}");
        assert_eq!(names.len(), 13 * 2);
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
    }

    /// The temp name no longer grows with the key or with the process's sequence
    /// counter: a 125-byte key still writes after the counter is large.
    #[tokio::test]
    async fn the_key_limit_does_not_drift_with_the_temp_sequence() {
        let s = ObjectStore::open(root("tmpseq")).unwrap();
        s.create_bucket("bkt").await.unwrap();
        TMP_SEQ.fetch_add(10_000_000_000, Ordering::Relaxed);
        let key = key_of(HEX_NAME_MAX_KEY, "a");
        s.put_object("bkt", &key, &b"x"[..], "t", None).await.unwrap();
        assert_eq!(object_stem(&key), hex(key.as_bytes()));
    }

    /// Objects written by the previous naming (`hex(key)` for every key, up to the 123
    /// bytes its temp name allowed) are read, listed, overwritten and deleted unchanged.
    #[tokio::test]
    async fn objects_stored_under_the_old_naming_stay_readable() {
        let dir = root("legacy");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let keys = ["a.txt".to_string(), key_of(116, "old"), key_of(123, "old")];
        for key in &keys {
            let hk = hex(key.as_bytes());
            std::fs::write(dir.join("bkt").join(&hk), b"legacy").unwrap();
            let meta = ObjectMeta {
                key: key.clone(),
                size: 6,
                etag: "e".into(),
                content_type: "text/plain".into(),
                last_modified: 1,
                cache_control: None,
            };
            std::fs::write(
                dir.join("bkt").join(format!("{hk}.meta")),
                serde_json::to_vec(&meta).unwrap(),
            )
            .unwrap();
        }
        for key in &keys {
            let (meta, f) = s.get_object("bkt", key).await.unwrap();
            assert_eq!(&meta.key, key);
            assert_eq!(read_all(f).await, b"legacy");
        }
        let listed: Vec<String> = s
            .list_objects("bkt", "", None, 1000)
            .await
            .unwrap()
            .objects
            .into_iter()
            .map(|m| m.key)
            .collect();
        let mut want = keys.to_vec();
        want.sort();
        assert_eq!(listed, want);
        // Overwrite lands on the same files (no second copy under a new name).
        s.put_object("bkt", &keys[2], &b"new"[..], "t", None).await.unwrap();
        assert_eq!(s.usage_counts().await.unwrap(), (1, 3));
        assert_eq!(read_all(s.get_object("bkt", &keys[2]).await.unwrap().1).await, b"new");
        s.delete_object("bkt", &keys[1]).await.unwrap();
        assert_eq!(s.usage_counts().await.unwrap(), (1, 2));
    }

    #[tokio::test]
    async fn long_keys_overwrite_delete_and_multipart() {
        let dir = root("longops");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let key = key_of(700, "a");
        s.put_object("bkt", &key, &b"one"[..], "t", None).await.unwrap();
        s.put_object("bkt", &key, &b"two!"[..], "t", None).await.unwrap();
        assert_eq!(s.usage_counts().await.unwrap(), (1, 1));
        assert_eq!(s.object_size("bkt", &key).await.unwrap(), Some(4));
        s.delete_object("bkt", &key).await.unwrap();
        assert!(matches!(
            s.get_object("bkt", &key).await,
            Err(ObjectError::NoSuchKey(_))
        ));
        assert_eq!(std::fs::read_dir(dir.join("bkt")).unwrap().count(), 0);

        let mp = key_of(1024, "mp");
        let id = s.create_multipart("bkt", &mp, "t", None).await.unwrap();
        s.upload_part("bkt", &id, 1, &b"hello "[..], None).await.unwrap();
        s.upload_part("bkt", &id, 2, &b"world"[..], None).await.unwrap();
        s.complete_multipart("bkt", &mp, &id, &[1, 2]).await.unwrap();
        assert_eq!(read_all(s.get_object("bkt", &mp).await.unwrap().1).await, b"hello world");
        s.delete_object("bkt", &mp).await.unwrap();
        // Bucket is empty again (no stray temp / staging), so it can be deleted.
        s.delete_bucket("bkt").await.unwrap();
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
            keys.push(format!("bundle-inputs/{}/{i:04}/{}.tar.gz", "k".repeat(40), "n".repeat(80)));
        }
        for k in &keys {
            s.put_object("bkt", k, k.as_bytes(), "t", None).await.unwrap();
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

    /// A hashed name is not the key: a sidecar found under it that names another key is
    /// never served or listed.
    #[tokio::test]
    async fn a_long_name_never_serves_another_key() {
        let dir = root("longmismatch");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let (a, b) = (key_of(300, "a"), key_of(300, "b"));
        s.put_object("bkt", &a, &b"A"[..], "t", None).await.unwrap();
        // Move A's files under B's name (as corruption / tampering would).
        let (sa, sb) = (object_stem(&a), object_stem(&b));
        for suffix in ["", ".meta"] {
            std::fs::rename(
                dir.join("bkt").join(format!("{sa}{suffix}")),
                dir.join("bkt").join(format!("{sb}{suffix}")),
            )
            .unwrap();
        }
        assert!(matches!(
            s.get_object("bkt", &b).await,
            Err(ObjectError::NoSuchKey(_))
        ));
        assert!(s.list_objects("bkt", "", None, 10).await.unwrap().objects.is_empty());
    }

    #[test]
    fn stems_fit_the_filesystem_and_never_overlap() {
        let fits = |n: usize| object_stem(&key_of(n, "a")).len() + META_SUFFIX.len();
        assert_eq!(fits(HEX_NAME_MAX_KEY), NAME_MAX);
        assert_eq!(fits(B64_NAME_MAX_KEY), NAME_MAX);
        assert_eq!(fits(B64_NAME_MAX_KEY + 1), NAME_MAX);
        assert_eq!(fits(1024), NAME_MAX);
        for n in 1..=1024 {
            let mut key = "é😀/".repeat(n / 7 + 1);
            while !key.is_char_boundary(n) {
                key.insert(0, 'p');
            }
            key.truncate(n);
            let stem = object_stem(&key);
            assert!(stem.len() + META_SUFFIX.len() <= NAME_MAX, "{n}");
            assert!(!stem.contains('/') && !stem.starts_with('.'), "{n}");
            match parse_stem(&stem) {
                Some(StemKey::Exact(k)) => assert!(n <= B64_NAME_MAX_KEY && k == key, "{n}"),
                Some(StemKey::Head(h)) => {
                    assert!(n > B64_NAME_MAX_KEY && key.as_bytes().starts_with(&h), "{n}")
                }
                None => panic!("{n}: own stem did not parse"),
            }
            // A reader that only knows `hex(key)` names must skip the new ones.
            assert_eq!(hex_decode(&stem).is_ok(), n <= HEX_NAME_MAX_KEY, "{n}");
        }
        // Same head, different key → different file.
        let head = "p".repeat(300);
        assert_ne!(object_stem(&format!("{head}1")), object_stem(&format!("{head}2")));
        // One name per key: a short key dressed up in a longer tier's name is not listed.
        assert!(parse_stem(&format!("{B64_NAME_PREFIX}{}", b64(b"short"))).is_none());
        assert!(parse_stem("4A").is_none() && parse_stem("4a").is_some());
    }

    #[test]
    fn b64_round_trips_and_rejects_non_canonical_names() {
        for len in 0..=200usize {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 131 + len * 7) as u8).collect();
            let enc = b64(&bytes);
            assert_eq!(enc.len(), (len * 4).div_ceil(3));
            assert_eq!(b64_decode(&enc).as_deref(), Some(&bytes[..]), "{len}");
        }
        assert!(b64_decode("A").is_none()); // impossible length
        assert!(b64_decode("AA=").is_none()); // outside the alphabet
        assert!(b64_decode("--0").is_none()); // stray low bits: not what b64 writes
        assert!(b64_decode("/-").is_none());
    }

    /// Listings of one store queue past `MAX_CONCURRENT_LISTS` instead of running at
    /// once, and all complete.
    #[tokio::test]
    async fn concurrent_listings_are_bounded_and_all_complete() {
        let s = std::sync::Arc::new(ObjectStore::open(root("listcap")).unwrap());
        s.create_bucket("bkt").await.unwrap();
        s.put_object("bkt", "a", &b"x"[..], "t", None).await.unwrap();
        let held = s
            .list_permits
            .acquire_many(MAX_CONCURRENT_LISTS as u32)
            .await
            .unwrap();
        let mut tasks = tokio::task::JoinSet::new();
        for _ in 0..3 * MAX_CONCURRENT_LISTS {
            let s = s.clone();
            tasks.spawn(async move {
                s.list_objects("bkt", "", None, 10).await.unwrap().objects.len()
            });
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(tasks.try_join_next().is_none(), "a listing ran past the cap");
        drop(held);
        while let Some(n) = tasks.join_next().await {
            assert_eq!(n.unwrap(), 1);
        }
    }
    /// Keys up to 186 bytes are listed from file names alone: the scan must not depend
    /// on (or pay for) any sidecar but the returned page's own.
    #[tokio::test]
    async fn whole_key_names_list_without_reading_other_sidecars() {
        let dir = root("noread");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("bkt").await.unwrap();
        let keys: Vec<String> = (0..20)
            .map(|i| format!("{}/{i:02}", "p".repeat(B64_NAME_MAX_KEY - 3)))
            .collect();
        for k in &keys {
            assert_eq!(k.len(), B64_NAME_MAX_KEY);
            s.put_object("bkt", k, &b"x"[..], "t", None).await.unwrap();
        }
        // Wreck every sidecar except the first key's.
        for k in &keys[1..] {
            let meta = dir.join("bkt").join(format!("{}.meta", object_stem(k)));
            std::fs::write(meta, b"not json").unwrap();
        }
        let page = s.list_v2("bkt", "", None, None, 1).await.unwrap();
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, keys[0]);
        assert!(page.is_truncated);
        assert_eq!(page.next_continuation_token.as_deref(), Some(keys[0].as_str()));
        // Folding never needs them either.
        let folded = s.list_v2("bkt", "", Some("/"), None, 10).await.unwrap();
        assert_eq!(folded.common_prefixes, vec![format!("{}/", "p".repeat(B64_NAME_MAX_KEY - 3))]);
    }
}
