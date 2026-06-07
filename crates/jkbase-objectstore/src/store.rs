use md5::{Digest, Md5};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWriteExt};

static TMP_SEQ: AtomicU64 = AtomicU64::new(0);

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
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

/// Per-upload info persisted at multipart-initiate (the final object's key +
/// content-type, applied at complete).
#[derive(Serialize, Deserialize)]
struct UploadInfo {
    key: String,
    content_type: String,
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
        let _ = tokio::fs::remove_file(self.root.join(".owners").join(bucket)).await;
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

    /// Record the owning tenant of `bucket` (for per-tenant isolation). Stored
    /// outside the bucket dir so it never blocks bucket deletion or shows in lists.
    pub async fn set_bucket_owner(&self, bucket: &str, owner: &str) -> Result<()> {
        validate_bucket(bucket)?;
        let odir = self.root.join(".owners");
        tokio::fs::create_dir_all(&odir).await?;
        tokio::fs::write(odir.join(bucket), owner).await?;
        Ok(())
    }

    /// The tenant that owns `bucket`, if recorded.
    pub async fn bucket_owner(&self, bucket: &str) -> Result<Option<String>> {
        validate_bucket(bucket)?;
        match tokio::fs::read_to_string(self.root.join(".owners").join(bucket)).await {
            Ok(s) => Ok(Some(s.trim().to_string())),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
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
    pub async fn put_object<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        key: &str,
        mut reader: R,
        content_type: &str,
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

        let mut hasher = Md5::new();
        let mut size = 0u64;
        {
            let mut f = tokio::fs::File::create(&tmp).await?;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                f.write_all(&buf[..n]).await?;
                size += n as u64;
            }
            f.sync_all().await?;
        }
        if let Err(e) = tokio::fs::rename(&tmp, &obj).await {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(e.into());
        }

        let meta = ObjectMeta {
            key: key.to_string(),
            size,
            etag: hex(&hasher.finalize()),
            content_type: content_type.to_string(),
            last_modified: now_secs(),
        };
        tokio::fs::write(dir.join(format!("{hk}.meta")), serde_json::to_vec(&meta).unwrap()).await?;
        Ok(meta)
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
    pub async fn list_objects(&self, bucket: &str, prefix: &str) -> Result<Vec<ObjectMeta>> {
        let dir = self.require_bucket(bucket).await?;
        let mut out = Vec::new();
        let mut rd = tokio::fs::read_dir(&dir).await?;
        while let Some(entry) = rd.next_entry().await? {
            let name = entry.file_name().to_string_lossy().into_owned();
            if !name.ends_with(".meta") {
                continue;
            }
            let bytes = tokio::fs::read(entry.path()).await?;
            let meta: ObjectMeta = serde_json::from_slice(&bytes)
                .map_err(|_| ObjectError::CorruptMeta(name.clone()))?;
            if meta.key.starts_with(prefix) {
                out.push(meta);
            }
        }
        out.sort_by(|a, b| a.key.cmp(&b.key));
        Ok(out)
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
        };
        tokio::fs::write(sdir.join("info.json"), serde_json::to_vec(&info).unwrap()).await?;
        Ok(upload_id)
    }

    /// Upload one part (number 1..=10000), streamed; returns its hex-MD5 etag.
    pub async fn upload_part<R: AsyncRead + Unpin>(
        &self,
        bucket: &str,
        upload_id: &str,
        part_number: u32,
        mut reader: R,
    ) -> Result<String> {
        if !(1..=10_000).contains(&part_number) {
            return Err(ObjectError::InvalidArgument(format!("part number {part_number}")));
        }
        let sdir = self.staging(bucket, upload_id).await?;
        let part = sdir.join(format!("part-{part_number}"));
        let tmp = sdir.join(format!("part-{part_number}.tmp"));
        let mut hasher = Md5::new();
        {
            let mut f = tokio::fs::File::create(&tmp).await?;
            let mut buf = vec![0u8; 256 * 1024];
            loop {
                let n = reader.read(&mut buf).await?;
                if n == 0 {
                    break;
                }
                hasher.update(&buf[..n]);
                f.write_all(&buf[..n]).await?;
            }
            f.sync_all().await?;
        }
        tokio::fs::rename(&tmp, &part).await?;
        let raw = hasher.finalize();
        // Persist the raw 16-byte digest; the final multipart etag is md5-of-md5s.
        tokio::fs::write(sdir.join(format!("part-{part_number}.md5")), raw).await?;
        Ok(hex(&raw))
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
        let dir = self.root.join(bucket);
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
        tokio::fs::write(dir.join(format!("{hk}.meta")), serde_json::to_vec(&meta).unwrap()).await?;
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
        let meta = s.put_object("my-bucket", "a/b/c.txt", &body[..], "text/plain").await.unwrap();
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
        s.put_object("flatbucket", "a/b", &b"1"[..], "x").await.unwrap();
        s.put_object("flatbucket", "a/b/c", &b"2"[..], "x").await.unwrap();
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
        s.put_object("bucket-one", "img/a", &b"x"[..], "x").await.unwrap();
        s.put_object("bucket-one", "img/b", &b"x"[..], "x").await.unwrap();
        s.put_object("bucket-one", "doc/c", &b"x"[..], "x").await.unwrap();
        s.put_object("bucket-two", "img/z", &b"x"[..], "x").await.unwrap();

        let keys: Vec<_> = s.list_objects("bucket-one", "img/").await.unwrap().into_iter().map(|m| m.key).collect();
        assert_eq!(keys, vec!["img/a".to_string(), "img/b".to_string()]);
        // Isolation: b2's object never shows up under b1.
        assert_eq!(s.list_objects("bucket-two", "").await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn errors_for_missing_bucket_and_invalid_names() {
        let dir = root("err");
        let s = ObjectStore::open(&dir).unwrap();
        assert!(matches!(s.put_object("nope", "k", &b""[..], "x").await, Err(ObjectError::NoSuchBucket(_))));
        assert!(matches!(s.create_bucket("AB").await, Err(ObjectError::InvalidBucketName(_)))); // too short + uppercase
        s.create_bucket("ok-bucket").await.unwrap();
        assert!(matches!(s.create_bucket("ok-bucket").await, Err(ObjectError::BucketAlreadyExists(_))));
        s.put_object("ok-bucket", "k", &b"x"[..], "x").await.unwrap();
        assert!(matches!(s.delete_bucket("ok-bucket").await, Err(ObjectError::BucketNotEmpty(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn multipart_concatenates_parts_in_order() {
        let dir = root("mpu");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("mp-bucket").await.unwrap();
        let uid = s.create_multipart("mp-bucket", "big/file", "application/octet-stream").await.unwrap();
        let e1 = s.upload_part("mp-bucket", &uid, 1, &b"hello "[..]).await.unwrap();
        let e2 = s.upload_part("mp-bucket", &uid, 2, &b"world"[..]).await.unwrap();
        assert_eq!(e1, format!("{:x}", Md5::digest(b"hello ")));
        assert_eq!(e2, format!("{:x}", Md5::digest(b"world")));

        let meta = s.complete_multipart("mp-bucket", "big/file", &uid, &[1, 2]).await.unwrap();
        assert_eq!(meta.size, 11);
        assert!(meta.etag.ends_with("-2")); // S3 multipart etag carries the part count
        assert_eq!(read_all(s.get_object("mp-bucket", "big/file").await.unwrap().1).await, b"hello world");

        // The upload id is consumed by complete.
        assert!(matches!(
            s.upload_part("mp-bucket", &uid, 3, &b"x"[..]).await,
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
        s.upload_part("ab-bucket", &uid, 1, &b"data"[..]).await.unwrap();
        s.abort_multipart("ab-bucket", &uid).await.unwrap();
        assert!(matches!(
            s.complete_multipart("ab-bucket", "k", &uid, &[1]).await,
            Err(ObjectError::NoSuchUpload(_))
        ));
        assert!(matches!(s.head_object("ab-bucket", "k").await, Err(ObjectError::NoSuchKey(_))));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn bucket_ownership_recorded_and_not_listed() {
        let dir = root("own");
        let s = ObjectStore::open(&dir).unwrap();
        s.create_bucket("tenant-bucket").await.unwrap();
        assert!(s.bucket_owner("tenant-bucket").await.unwrap().is_none());
        s.set_bucket_owner("tenant-bucket", "tenant-a").await.unwrap();
        assert_eq!(s.bucket_owner("tenant-bucket").await.unwrap().as_deref(), Some("tenant-a"));
        // The hidden .owners registry is never surfaced as a bucket.
        assert_eq!(s.list_buckets().await.unwrap(), vec!["tenant-bucket".to_string()]);
        // Deleting the bucket clears its owner record.
        s.delete_bucket("tenant-bucket").await.unwrap();
        assert!(s.bucket_owner("tenant-bucket").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
