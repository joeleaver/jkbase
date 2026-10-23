//! The index half of the object store: one redb file per project (`{root}/.index.redb`)
//! that is the single source of truth for which buckets, objects and multipart uploads
//! exist and which segments hold their bytes. Every visible change is one write
//! transaction; bytes are written before the transaction that makes them reachable and
//! deleted only after the one that makes them unreachable, so a crash can leak a segment
//! but never expose a torn object.
//!
//! Segment lifecycle (never requires listing the byte store, which may be remote):
//! `pending` (id recorded before a byte is written) → referenced by an object or part row
//! → `garbage` (unreachable, deleted after [`GRACE`] so in-flight GETs finish). A pending
//! id older than [`PENDING_ORPHAN_AGE`] is a write that crashed before committing.
//!
//! Every function here is blocking; the store calls them on the blocking pool. Values are
//! JSON so a field added later reads back from an older row (`#[serde(default)]`).

use crate::cors::CorsConfig;
use crate::store::{ListV2Page, MultipartUpload, ObjectError, ObjectMeta, UploadInfo};
use md5::{Digest, Md5};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::path::Path;

type Result<T> = std::result::Result<T, ObjectError>;

const BUCKETS: TableDefinition<&str, &[u8]> = TableDefinition::new("buckets");
/// `bucket \0 key` → [`ObjectRow`]. Neither half can contain NUL, so byte order within a
/// bucket is S3's key order.
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
/// `bucket \0 upload_id` → [`UploadInfo`].
const UPLOADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("uploads");
/// `upload_id \0 part_number (u32 BE)` → [`PartRow`].
const PARTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("parts");
/// segment id → unix secs the write began.
const PENDING: TableDefinition<&str, u64> = TableDefinition::new("pending");
/// segment id → unix secs from which it may be deleted.
const GARBAGE: TableDefinition<&str, u64> = TableDefinition::new("garbage");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// How long an unreachable segment stays readable. A GET holds a manifest snapshot and
/// opens its segments as it streams, so a segment deleted under it would cut the body
/// short (never serve wrong bytes — ids are never reused).
pub(crate) const GRACE: u64 = 3600;

/// A pending segment this old is a write whose process died before committing. Must
/// exceed the longest a write can legitimately run (the 6 h upload ceiling plus idle
/// reads), or the sweeper could reclaim a segment that is about to be referenced.
pub(crate) const PENDING_ORPHAN_AGE: u64 = 12 * 3600;

/// The index layout this binary writes. The legacy directory layout is 1.
pub(crate) const LAYOUT_V2: u64 = 2;

#[derive(Serialize, Deserialize, Default)]
struct BucketRow {
    created: u64,
    #[serde(default)]
    cors: Option<CorsConfig>,
}

/// One segment of an object, in object order.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq, Eq)]
pub(crate) struct SegRef {
    pub id: String,
    pub size: u64,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct ObjectRow {
    pub meta: ObjectMeta,
    pub segments: Vec<SegRef>,
}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub(crate) struct PartRow {
    pub segment: String,
    pub size: u64,
    /// Raw MD5 of the part, hex. The multipart etag is md5 over the raw digests.
    pub md5: String,
}

pub(crate) struct Index {
    db: Database,
}

impl From<redb::Error> for ObjectError {
    fn from(e: redb::Error) -> Self {
        ObjectError::Io(std::io::Error::other(format!("index: {e}")))
    }
}

macro_rules! via_redb_error {
    ($($t:ty),*) => {$(
        impl From<$t> for ObjectError {
            fn from(e: $t) -> Self {
                redb::Error::from(e).into()
            }
        }
    )*};
}
via_redb_error!(
    redb::DatabaseError,
    redb::TransactionError,
    redb::TableError,
    redb::StorageError,
    redb::CommitError
);

impl Index {
    /// Open (creating if absent) the index at `path`, with every table present so reads
    /// never meet a missing one.
    pub fn open(path: &Path) -> Result<Self> {
        let db = Database::create(path)?;
        let w = db.begin_write()?;
        {
            w.open_table(BUCKETS)?;
            w.open_table(OBJECTS)?;
            w.open_table(UPLOADS)?;
            w.open_table(PARTS)?;
            w.open_table(PENDING)?;
            w.open_table(GARBAGE)?;
            w.open_table(META)?;
        }
        w.commit()?;
        Ok(Self { db })
    }

    fn write<T>(&self, f: impl FnOnce(&WriteTransaction) -> Result<T>) -> Result<T> {
        let w = self.db.begin_write()?;
        // An Err drops `w`, which aborts the transaction: nothing partial is committed.
        let v = f(&w)?;
        w.commit()?;
        Ok(v)
    }

    pub fn layout(&self) -> Result<u64> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(META)?.get("layout")?.map_or(1, |v| v.value()))
    }

    pub fn set_layout(&self, v: u64) -> Result<()> {
        self.write(|w| {
            w.open_table(META)?.insert("layout", v)?;
            Ok(())
        })
    }

    // ---- buckets ----------------------------------------------------------

    pub fn create_bucket(&self, bucket: &str, now: u64) -> Result<()> {
        self.write(|w| {
            let mut t = w.open_table(BUCKETS)?;
            if t.get(bucket)?.is_some() {
                return Err(ObjectError::BucketAlreadyExists(bucket.to_string()));
            }
            t.insert(
                bucket,
                json(&BucketRow {
                    created: now,
                    cors: None,
                })
                .as_slice(),
            )?;
            Ok(())
        })
    }

    /// Create `bucket` if absent (migration); keeps an existing row as is.
    pub fn ensure_bucket(&self, bucket: &str, created: u64) -> Result<()> {
        self.write(|w| {
            let mut t = w.open_table(BUCKETS)?;
            if t.get(bucket)?.is_none() {
                t.insert(
                    bucket,
                    json(&BucketRow {
                        created,
                        cors: None,
                    })
                    .as_slice(),
                )?;
            }
            Ok(())
        })
    }

    /// S3 refuses to delete a bucket holding objects or unfinished multipart uploads.
    pub fn delete_bucket(&self, bucket: &str) -> Result<()> {
        self.write(|w| {
            let mut t = w.open_table(BUCKETS)?;
            if t.remove(bucket)?.is_none() {
                return Err(ObjectError::NoSuchBucket(bucket.to_string()));
            }
            let (lo, hi) = bucket_range(bucket);
            let occupied = w
                .open_table(OBJECTS)?
                .range(lo.as_slice()..hi.as_slice())?
                .next()
                .is_some()
                || w.open_table(UPLOADS)?
                    .range(lo.as_slice()..hi.as_slice())?
                    .next()
                    .is_some();
            if occupied {
                return Err(ObjectError::BucketNotEmpty(bucket.to_string()));
            }
            Ok(())
        })
    }

    pub fn list_buckets(&self) -> Result<Vec<String>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(BUCKETS)?;
        let mut out = Vec::new();
        for item in t.iter()? {
            out.push(item?.0.value().to_string());
        }
        Ok(out)
    }

    pub fn bucket_exists(&self, bucket: &str) -> Result<bool> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(BUCKETS)?.get(bucket)?.is_some())
    }

    pub fn get_cors(&self, bucket: &str) -> Result<Option<CorsConfig>> {
        let r = self.db.begin_read()?;
        let t = r.open_table(BUCKETS)?;
        Ok(t.get(bucket)?
            .and_then(|v| serde_json::from_slice::<BucketRow>(v.value()).ok())
            .and_then(|row| row.cors))
    }

    /// Set (or with `None`, clear) the bucket's CORS config. Clearing a missing bucket is
    /// a no-op; setting one is `NoSuchBucket`.
    pub fn set_cors(&self, bucket: &str, cors: Option<CorsConfig>) -> Result<()> {
        self.write(|w| {
            let mut t = w.open_table(BUCKETS)?;
            let Some(mut row) = t
                .get(bucket)?
                .map(|v| serde_json::from_slice::<BucketRow>(v.value()).unwrap_or_default())
            else {
                return match cors {
                    Some(_) => Err(ObjectError::NoSuchBucket(bucket.to_string())),
                    None => Ok(()),
                };
            };
            row.cors = cors;
            t.insert(bucket, json(&row).as_slice())?;
            Ok(())
        })
    }

    // ---- segments ---------------------------------------------------------

    /// Record `id` as being written. Must commit before any byte of it exists.
    pub fn add_pending(&self, id: &str, now: u64) -> Result<()> {
        self.write(|w| {
            w.open_table(PENDING)?.insert(id, now)?;
            Ok(())
        })
    }

    /// Give up on pending segments whose write failed or whose commit was refused: they
    /// become garbage, due immediately (nothing ever referenced them).
    pub fn discard_pending(&self, ids: &[String], now: u64) -> Result<()> {
        self.write(|w| {
            let mut p = w.open_table(PENDING)?;
            let mut g = w.open_table(GARBAGE)?;
            for id in ids {
                p.remove(id.as_str())?;
                g.insert(id.as_str(), now)?;
            }
            Ok(())
        })
    }

    /// Segments whose bytes may be deleted now: due garbage, plus pending ids old enough
    /// that their writer is certainly dead.
    pub fn due_segments(&self, now: u64) -> Result<Vec<String>> {
        let r = self.db.begin_read()?;
        let mut out = Vec::new();
        for item in r.open_table(GARBAGE)?.iter()? {
            let (id, due) = item?;
            if due.value() <= now {
                out.push(id.value().to_string());
            }
        }
        for item in r.open_table(PENDING)?.iter()? {
            let (id, since) = item?;
            if since.value().saturating_add(PENDING_ORPHAN_AGE) <= now {
                out.push(id.value().to_string());
            }
        }
        Ok(out)
    }

    /// Drop the bookkeeping for segments whose bytes are gone.
    pub fn forget_segments(&self, ids: &[String]) -> Result<()> {
        self.write(|w| {
            let mut p = w.open_table(PENDING)?;
            let mut g = w.open_table(GARBAGE)?;
            for id in ids {
                p.remove(id.as_str())?;
                g.remove(id.as_str())?;
            }
            Ok(())
        })
    }

    // ---- objects ----------------------------------------------------------

    pub fn get_object(&self, bucket: &str, key: &str) -> Result<ObjectRow> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        let t = r.open_table(OBJECTS)?;
        let v = t
            .get(obj_key(bucket, key).as_slice())?
            .ok_or_else(|| ObjectError::NoSuchKey(key.to_string()))?;
        serde_json::from_slice(v.value()).map_err(|_| ObjectError::CorruptMeta(key.to_string()))
    }

    /// Make `row` the object at `bucket/row.meta.key`, consuming its pending segments and
    /// retiring whatever it replaces. With `only_if_absent`, an existing object wins and
    /// `false` is returned (the caller discards its segments) — migration's idempotency.
    pub fn commit_object(
        &self,
        bucket: &str,
        row: &ObjectRow,
        now: u64,
        only_if_absent: bool,
    ) -> Result<bool> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let k = obj_key(bucket, &row.meta.key);
            let mut objects = w.open_table(OBJECTS)?;
            if only_if_absent && objects.get(k.as_slice())?.is_some() {
                return Ok(false);
            }
            take_pending(w, row.segments.iter().map(|s| s.id.as_str()))?;
            let old = objects
                .insert(k.as_slice(), json(row).as_slice())?
                .map(|v| v.value().to_vec());
            if let Some(old) = old {
                retire_object(w, &old, now)?;
            }
            Ok(true)
        })
    }

    /// Idempotent: a missing key is not an error (S3 semantics).
    pub fn delete_object(&self, bucket: &str, key: &str, now: u64) -> Result<()> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let old = w
                .open_table(OBJECTS)?
                .remove(obj_key(bucket, key).as_slice())?
                .map(|v| v.value().to_vec());
            if let Some(old) = old {
                retire_object(w, &old, now)?;
            }
            Ok(())
        })
    }

    /// ListObjectsV2 over the index — see [`crate::ObjectStore::list_v2`] for semantics.
    /// A range scan from `max(prefix, start_after)`: after emitting folder `f` the scan
    /// seeks to `f ++ 0xFF`, past every key under it (no UTF-8 key contains `0xFF`), so a
    /// folder with a million keys costs one step. Memory is O(max_keys).
    pub fn list(
        &self,
        bucket: &str,
        prefix: &str,
        delimiter: Option<&str>,
        start_after: Option<&str>,
        max_keys: usize,
    ) -> Result<ListV2Page> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        let t = r.open_table(OBJECTS)?;
        let base = obj_key(bucket, "");
        let (_, hi) = bucket_range(bucket);
        let delimiter = delimiter.filter(|d| !d.is_empty());
        let skip = |entry: &str| start_after.is_some_and(|sa| entry <= sa);

        let from = match start_after {
            Some(sa) if sa > prefix => sa,
            _ => prefix,
        };
        let mut lo = [base.as_slice(), from.as_bytes()].concat();
        // (sort key, metadata for an object / None for a folded folder)
        let mut entries: Vec<(String, Option<ObjectMeta>)> = Vec::new();
        'scan: loop {
            let mut resume = None;
            for item in t.range(lo.as_slice()..hi.as_slice())? {
                let (k, v) = item?;
                let Ok(key) = std::str::from_utf8(&k.value()[base.len()..]) else {
                    continue;
                };
                if !key.starts_with(prefix) {
                    break 'scan; // sorted: every later key is past the prefix too
                }
                let folder = delimiter.and_then(|d| {
                    key[prefix.len()..]
                        .find(d)
                        .map(|i| &key[..prefix.len() + i + d.len()])
                });
                if let Some(folder) = folder {
                    if !skip(folder) {
                        entries.push((folder.to_string(), None));
                    }
                    resume = Some([base.as_slice(), folder.as_bytes(), &[0xFF]].concat());
                    if entries.len() > max_keys {
                        break 'scan;
                    }
                    break;
                }
                if skip(key) {
                    continue;
                }
                let row: ObjectRow = serde_json::from_slice(v.value())
                    .map_err(|_| ObjectError::CorruptMeta(key.to_string()))?;
                entries.push((key.to_string(), Some(row.meta)));
                if entries.len() > max_keys {
                    break 'scan;
                }
            }
            match resume {
                Some(next) => lo = next,
                None => break,
            }
        }

        let is_truncated = entries.len() > max_keys;
        entries.truncate(max_keys);
        let next_continuation_token = if is_truncated {
            entries.last().map(|(k, _)| k.clone())
        } else {
            None
        };
        let mut objects = Vec::new();
        let mut common_prefixes = Vec::new();
        for (sort_key, meta) in entries {
            match meta {
                Some(meta) => objects.push(meta),
                None => common_prefixes.push(sort_key),
            }
        }
        Ok(ListV2Page {
            objects,
            common_prefixes,
            is_truncated,
            next_continuation_token,
        })
    }

    /// `(buckets, objects)` — O(1): redb keeps each table's length.
    pub fn counts(&self) -> Result<(u64, u64)> {
        let r = self.db.begin_read()?;
        Ok((r.open_table(BUCKETS)?.len()?, r.open_table(OBJECTS)?.len()?))
    }

    // ---- multipart --------------------------------------------------------

    pub fn create_upload(&self, bucket: &str, upload_id: &str, info: &UploadInfo) -> Result<()> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            w.open_table(UPLOADS)?.insert(
                upload_key(bucket, upload_id).as_slice(),
                json(info).as_slice(),
            )?;
            Ok(())
        })
    }

    /// Create the upload row if absent (migration); keeps an existing one.
    pub fn ensure_upload(&self, bucket: &str, upload_id: &str, info: &UploadInfo) -> Result<()> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let mut t = w.open_table(UPLOADS)?;
            let k = upload_key(bucket, upload_id);
            if t.get(k.as_slice())?.is_none() {
                t.insert(k.as_slice(), json(info).as_slice())?;
            }
            Ok(())
        })
    }

    pub fn upload_exists(&self, bucket: &str, upload_id: &str) -> Result<bool> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        Ok(r.open_table(UPLOADS)?
            .get(upload_key(bucket, upload_id).as_slice())?
            .is_some())
    }

    /// Record part `part` of an upload, retiring a part it replaces (S3 lets a client
    /// re-upload a part number). With `only_if_absent`, an existing part wins.
    pub fn commit_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part: u32,
        row: &PartRow,
        now: u64,
        only_if_absent: bool,
    ) -> Result<bool> {
        self.write(|w| {
            require_upload(w, bucket, upload_id)?;
            let k = part_key(upload_id, part);
            let mut parts = w.open_table(PARTS)?;
            if only_if_absent && parts.get(k.as_slice())?.is_some() {
                return Ok(false);
            }
            take_pending(w, std::iter::once(row.segment.as_str()))?;
            let old = parts
                .insert(k.as_slice(), json(row).as_slice())?
                .map(|v| v.value().to_vec());
            if let Some(old) = old
                && let Ok(old) = serde_json::from_slice::<PartRow>(&old)
            {
                w.open_table(GARBAGE)?
                    .insert(old.segment.as_str(), now + GRACE)?;
            }
            Ok(true)
        })
    }

    /// Complete an upload: the object's segments ARE the listed parts' segments, in
    /// order — no byte is copied. Parts uploaded but not listed are retired. The etag is
    /// S3's `md5(concat of part md5s)-<count>`.
    pub fn complete_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_numbers: &[u32],
        now: u64,
    ) -> Result<ObjectMeta> {
        self.write(|w| {
            let info = require_upload(w, bucket, upload_id)?;
            if info.key != key {
                return Err(ObjectError::InvalidArgument(
                    "key does not match upload".into(),
                ));
            }
            if part_numbers.is_empty() {
                return Err(ObjectError::InvalidArgument("no parts".into()));
            }
            if part_numbers.windows(2).any(|p| p[0] >= p[1]) {
                return Err(ObjectError::InvalidArgument(
                    "parts must be listed in ascending order without repeats".into(),
                ));
            }
            let mut parts = w.open_table(PARTS)?;
            let (lo, hi) = upload_part_range(upload_id);
            let mut staged = Vec::new();
            for item in parts.range(lo.as_slice()..hi.as_slice())? {
                let (k, v) = item?;
                let pn = u32::from_be_bytes(k.value()[lo.len()..].try_into().unwrap_or_default());
                let row: PartRow = serde_json::from_slice(v.value())
                    .map_err(|_| ObjectError::CorruptMeta(upload_id.to_string()))?;
                staged.push((k.value().to_vec(), pn, row));
            }
            let mut concat = Md5::new();
            let mut segments = Vec::with_capacity(part_numbers.len());
            for &pn in part_numbers {
                let Some((_, _, row)) = staged.iter().find(|(_, p, _)| *p == pn) else {
                    return Err(ObjectError::InvalidArgument(format!("missing part {pn}")));
                };
                concat.update(unhex(&row.md5));
                segments.push(SegRef {
                    id: row.segment.clone(),
                    size: row.size,
                });
            }
            let mut garbage = w.open_table(GARBAGE)?;
            for (k, pn, row) in &staged {
                parts.remove(k.as_slice())?;
                if !part_numbers.contains(pn) {
                    garbage.insert(row.segment.as_str(), now + GRACE)?;
                }
            }
            drop(garbage);
            w.open_table(UPLOADS)?
                .remove(upload_key(bucket, upload_id).as_slice())?;
            let meta = ObjectMeta {
                key: key.to_string(),
                size: segments.iter().map(|s| s.size).sum(),
                etag: format!("{}-{}", hex(&concat.finalize()), part_numbers.len()),
                content_type: info.content_type,
                last_modified: now,
                cache_control: info.cache_control,
            };
            let row = ObjectRow {
                meta: meta.clone(),
                segments,
            };
            let old = w
                .open_table(OBJECTS)?
                .insert(obj_key(bucket, key).as_slice(), json(&row).as_slice())?
                .map(|v| v.value().to_vec());
            if let Some(old) = old {
                retire_object(w, &old, now)?;
            }
            Ok(meta)
        })
    }

    pub fn abort_upload(&self, bucket: &str, upload_id: &str, now: u64) -> Result<()> {
        self.write(|w| {
            require_upload(w, bucket, upload_id)?;
            drop_upload(w, bucket, upload_id, now)
        })
    }

    pub fn list_uploads(&self, bucket: &str) -> Result<Vec<MultipartUpload>> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        let (lo, hi) = bucket_range(bucket);
        let mut out = Vec::new();
        for item in r.open_table(UPLOADS)?.range(lo.as_slice()..hi.as_slice())? {
            let (k, v) = item?;
            let Ok(info) = serde_json::from_slice::<UploadInfo>(v.value()) else {
                continue;
            };
            out.push(MultipartUpload {
                upload_id: String::from_utf8_lossy(&k.value()[lo.len()..]).into_owned(),
                key: info.key,
                initiated: info.initiated,
            });
        }
        Ok(out)
    }

    /// Abort every upload initiated at or before `threshold`; returns how many.
    pub fn abort_uploads_before(&self, threshold: u64, now: u64) -> Result<usize> {
        self.write(|w| {
            let mut stale = Vec::new();
            for item in w.open_table(UPLOADS)?.iter()? {
                let (k, v) = item?;
                let initiated =
                    serde_json::from_slice::<UploadInfo>(v.value()).map_or(0, |i| i.initiated);
                if initiated <= threshold {
                    stale.push(k.value().to_vec());
                }
            }
            for k in &stale {
                let Some(nul) = k.iter().position(|&b| b == 0) else {
                    continue;
                };
                let bucket = String::from_utf8_lossy(&k[..nul]).into_owned();
                let upload_id = String::from_utf8_lossy(&k[nul + 1..]).into_owned();
                drop_upload(w, &bucket, &upload_id, now)?;
            }
            Ok(stale.len())
        })
    }

    pub fn upload_count(&self) -> Result<u64> {
        let r = self.db.begin_read()?;
        Ok(r.open_table(UPLOADS)?.len()?)
    }
}

// ---- transaction helpers ----------------------------------------------------

fn require_bucket(w: &WriteTransaction, bucket: &str) -> Result<()> {
    if w.open_table(BUCKETS)?.get(bucket)?.is_none() {
        return Err(ObjectError::NoSuchBucket(bucket.to_string()));
    }
    Ok(())
}

fn require_upload(w: &WriteTransaction, bucket: &str, upload_id: &str) -> Result<UploadInfo> {
    require_bucket(w, bucket)?;
    let t = w.open_table(UPLOADS)?;
    let v = t
        .get(upload_key(bucket, upload_id).as_slice())?
        .ok_or_else(|| ObjectError::NoSuchUpload(upload_id.to_string()))?;
    serde_json::from_slice(v.value()).map_err(|_| ObjectError::CorruptMeta(upload_id.to_string()))
}

/// Consume pending ids into a reference. A pending row that is gone means the sweeper
/// already judged the write dead and may have deleted its bytes: refuse rather than
/// reference a segment that might not exist.
fn take_pending<'a>(w: &WriteTransaction, ids: impl Iterator<Item = &'a str>) -> Result<()> {
    let mut p = w.open_table(PENDING)?;
    for id in ids {
        if p.remove(id)?.is_none() {
            return Err(ObjectError::Io(std::io::Error::other(format!(
                "segment {id} is no longer pending"
            ))));
        }
    }
    Ok(())
}

fn retire_object(w: &WriteTransaction, row: &[u8], now: u64) -> Result<()> {
    let Ok(row) = serde_json::from_slice::<ObjectRow>(row) else {
        return Ok(()); // unreadable row: nothing we can name to reclaim
    };
    let mut g = w.open_table(GARBAGE)?;
    for s in &row.segments {
        g.insert(s.id.as_str(), now + GRACE)?;
    }
    Ok(())
}

fn drop_upload(w: &WriteTransaction, bucket: &str, upload_id: &str, now: u64) -> Result<()> {
    let mut parts = w.open_table(PARTS)?;
    let (lo, hi) = upload_part_range(upload_id);
    let mut doomed = Vec::new();
    for item in parts.range(lo.as_slice()..hi.as_slice())? {
        let (k, v) = item?;
        let seg = serde_json::from_slice::<PartRow>(v.value())
            .ok()
            .map(|r| r.segment);
        doomed.push((k.value().to_vec(), seg));
    }
    let mut g = w.open_table(GARBAGE)?;
    for (k, seg) in doomed {
        parts.remove(k.as_slice())?;
        if let Some(seg) = seg {
            g.insert(seg.as_str(), now + GRACE)?;
        }
    }
    w.open_table(UPLOADS)?
        .remove(upload_key(bucket, upload_id).as_slice())?;
    Ok(())
}

// ---- keys -------------------------------------------------------------------

fn obj_key(bucket: &str, key: &str) -> Vec<u8> {
    [bucket.as_bytes(), &[0], key.as_bytes()].concat()
}

fn upload_key(bucket: &str, upload_id: &str) -> Vec<u8> {
    [bucket.as_bytes(), &[0], upload_id.as_bytes()].concat()
}

fn part_key(upload_id: &str, part: u32) -> Vec<u8> {
    [upload_id.as_bytes(), &[0], &part.to_be_bytes()].concat()
}

/// Every `bucket \0 …` key: `[bucket \0, bucket \1)`.
fn bucket_range(bucket: &str) -> (Vec<u8>, Vec<u8>) {
    (
        [bucket.as_bytes(), &[0]].concat(),
        [bucket.as_bytes(), &[1]].concat(),
    )
}

fn upload_part_range(upload_id: &str) -> (Vec<u8>, Vec<u8>) {
    (
        [upload_id.as_bytes(), &[0]].concat(),
        [upload_id.as_bytes(), &[1]].concat(),
    )
}

fn json<T: Serialize>(v: &T) -> Vec<u8> {
    serde_json::to_vec(v).expect("index rows always serialize")
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len() / 2)
        .filter_map(|i| u8::from_str_radix(s.get(2 * i..2 * i + 2)?, 16).ok())
        .collect()
}
