//! The index half of the object store: one redb file per project (`{root}/.index.redb`)
//! that is the single source of truth for which buckets, objects and multipart uploads
//! exist and which segments hold their bytes. Every visible change is one write
//! transaction; bytes are written before the transaction that makes them reachable and
//! deleted only after the one that makes them unreachable, so a crash can leak a segment
//! but never expose a torn object.
//!
//! Segment lifecycle (never requires listing the byte store, which may be remote):
//! `pending` (id recorded before a byte is written) → referenced by an object or part row
//! → `garbage` (unreachable). Garbage is deletable at once; the store deletes it right
//! after the transaction that retired it unless a GET in this process still has it
//! pinned (see `store::Pins`), and the sweeper retries what is left. A pending id older
//! than [`PENDING_ORPHAN_AGE`] is a write that crashed before committing. Every mutation
//! returns the ids it retired.
//!
//! Every function here is blocking; the store calls them on the blocking pool. Values are
//! JSON so a field added later reads back from an older row (`#[serde(default)]`).

use crate::cors::CorsConfig;
use crate::store::{ListV2Page, MultipartUpload, ObjectError, ObjectMeta, UploadInfo};
use md5::{Digest, Md5};
use redb::{Database, ReadableTable, ReadableTableMetadata, TableDefinition, WriteTransaction};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::path::Path;

type Result<T> = std::result::Result<T, ObjectError>;

const BUCKETS: TableDefinition<&str, &[u8]> = TableDefinition::new("buckets");
/// `bucket \0 key` → [`ObjectMeta`]. Neither half can contain NUL, so byte order within
/// a bucket is S3's key order.
const OBJECTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("objects");
/// `bucket \0 key` → `Vec<SegRef>`, apart from the metadata so HEAD and LIST never parse
/// a manifest (up to 10 000 entries for a multipart object).
const MANIFESTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("manifests");
/// `bucket \0 upload_id` → [`UploadInfo`].
const UPLOADS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("uploads");
/// `upload_id \0 part_number (u32 BE)` → [`PartRow`].
const PARTS: TableDefinition<&[u8], &[u8]> = TableDefinition::new("parts");
/// segment id → unix secs the write began.
const PENDING: TableDefinition<&str, u64> = TableDefinition::new("pending");
/// segment id → unix secs it became unreachable.
const GARBAGE: TableDefinition<&str, u64> = TableDefinition::new("garbage");
const META: TableDefinition<&str, u64> = TableDefinition::new("meta");

/// A pending segment this old is a write whose process died before committing. Must
/// exceed the longest a write can legitimately run (the 6 h upload ceiling plus idle
/// reads). A wall-clock jump can still make a live write look dead; [`Index::claim_due`]
/// then retires its id first, so that write fails its commit rather than reference bytes
/// being deleted.
pub(crate) const PENDING_ORPHAN_AGE: u64 = 12 * 3600;

/// S3's minimum size for every part of a multipart upload but the last. Without it an
/// object could be 10 000 one-byte segments: a 10 000-entry manifest and a file open per
/// segment on every GET of it.
pub(crate) const MIN_PART_SIZE: u64 = 5 * 1024 * 1024;

/// Page cache per open index. redb's default (1 GiB) is per database, and the server keeps
/// thousands of project stores open.
const CACHE_BYTES: usize = 8 * 1024 * 1024;

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

/// An object as the store sees it: its metadata plus its segment manifest.
#[derive(Clone, Debug)]
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

/// Segment ids a mutation made unreachable.
pub(crate) type Retired = Vec<String>;

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
        // The redb file lock outlives the last handle by the moment its `Drop` takes to
        // flush, so a reopen racing a close can briefly see "already open": wait it out.
        let mut tries = 0;
        let db = loop {
            match redb::Builder::new()
                .set_cache_size(CACHE_BYTES)
                .create(path)
            {
                Err(redb::DatabaseError::DatabaseAlreadyOpen) if tries < 100 => {
                    tries += 1;
                    std::thread::sleep(std::time::Duration::from_millis(20));
                }
                r => break r?,
            }
        };
        let w = db.begin_write()?;
        {
            w.open_table(BUCKETS)?;
            w.open_table(OBJECTS)?;
            w.open_table(MANIFESTS)?;
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
            let row = BucketRow {
                created: now,
                cors: None,
            };
            t.insert(bucket, json(&row).as_slice())?;
            Ok(())
        })
    }

    /// Create `bucket` if absent (migration); keeps an existing row as is.
    pub fn ensure_bucket(&self, bucket: &str, created: u64) -> Result<()> {
        self.write(|w| {
            let mut t = w.open_table(BUCKETS)?;
            if t.get(bucket)?.is_none() {
                let row = BucketRow {
                    created,
                    cors: None,
                };
                t.insert(bucket, json(&row).as_slice())?;
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

    /// Record `ids` as being written. Must commit before any byte of them exists.
    pub fn add_pending(&self, ids: &[String], now: u64) -> Result<()> {
        self.write(|w| {
            let mut p = w.open_table(PENDING)?;
            for id in ids {
                p.insert(id.as_str(), now)?;
            }
            Ok(())
        })
    }

    /// Give up on pending segments whose write failed or whose commit was refused: they
    /// become garbage (nothing ever referenced them).
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

    /// Claim up to `limit` segments whose bytes may be deleted: garbage, after first
    /// retiring pending ids old enough that their writer is certainly dead. Retiring them
    /// happens in this transaction, BEFORE any byte is deleted, so a writer that turns
    /// out to be alive after all fails its commit in `take_pending` instead of
    /// referencing a segment being deleted under it.
    pub fn claim_due(&self, now: u64, limit: usize) -> Result<Vec<String>> {
        self.write(|w| {
            let mut p = w.open_table(PENDING)?;
            let mut stale = Vec::new();
            for item in p.iter()? {
                let (id, since) = item?;
                if since.value().saturating_add(PENDING_ORPHAN_AGE) <= now {
                    stale.push(id.value().to_string());
                }
            }
            let mut g = w.open_table(GARBAGE)?;
            for id in &stale {
                p.remove(id.as_str())?;
                g.insert(id.as_str(), now)?;
            }
            let mut out = Vec::new();
            for item in g.iter()?.take(limit) {
                out.push(item?.0.value().to_string());
            }
            Ok(out)
        })
    }

    /// Drop the bookkeeping for garbage whose bytes are gone.
    pub fn forget_segments(&self, ids: &[String]) -> Result<()> {
        self.write(|w| {
            let mut g = w.open_table(GARBAGE)?;
            for id in ids {
                g.remove(id.as_str())?;
            }
            Ok(())
        })
    }

    // ---- objects ----------------------------------------------------------

    pub fn get_meta(&self, bucket: &str, key: &str) -> Result<ObjectMeta> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        let v = r
            .open_table(OBJECTS)?
            .get(obj_key(bucket, key).as_slice())?
            .ok_or_else(|| ObjectError::NoSuchKey(key.to_string()))?;
        serde_json::from_slice(v.value()).map_err(|_| ObjectError::CorruptMeta(key.to_string()))
    }

    /// Metadata and manifest, read in one snapshot.
    pub fn get_object(&self, bucket: &str, key: &str) -> Result<ObjectRow> {
        let r = self.db.begin_read()?;
        if r.open_table(BUCKETS)?.get(bucket)?.is_none() {
            return Err(ObjectError::NoSuchBucket(bucket.to_string()));
        }
        let k = obj_key(bucket, key);
        let corrupt = || ObjectError::CorruptMeta(key.to_string());
        let meta = r
            .open_table(OBJECTS)?
            .get(k.as_slice())?
            .ok_or_else(|| ObjectError::NoSuchKey(key.to_string()))?;
        let meta: ObjectMeta = serde_json::from_slice(meta.value()).map_err(|_| corrupt())?;
        let segments = r
            .open_table(MANIFESTS)?
            .get(k.as_slice())?
            .ok_or_else(corrupt)?;
        let segments = serde_json::from_slice(segments.value()).map_err(|_| corrupt())?;
        Ok(ObjectRow { meta, segments })
    }

    /// Make `row` the object at `bucket/row.meta.key`, consuming its pending segments and
    /// retiring whatever it replaces.
    pub fn commit_object(&self, bucket: &str, row: &ObjectRow, now: u64) -> Result<Retired> {
        self.commit_objects(bucket, std::slice::from_ref(row), now)
    }

    /// [`commit_object`](Self::commit_object) for many rows in one transaction (one
    /// fsync) — the migration's batch.
    pub fn commit_objects(&self, bucket: &str, rows: &[ObjectRow], now: u64) -> Result<Retired> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let mut retired = Vec::new();
            for row in rows {
                take_pending(w, row.segments.iter().map(|s| s.id.as_str()))?;
                let k = obj_key(bucket, &row.meta.key);
                w.open_table(OBJECTS)?
                    .insert(k.as_slice(), json(&row.meta).as_slice())?;
                let old = w
                    .open_table(MANIFESTS)?
                    .insert(k.as_slice(), json(&row.segments).as_slice())?
                    .map(|v| v.value().to_vec());
                if let Some(old) = old {
                    retire_manifest(w, &old, now, &mut retired)?;
                }
            }
            Ok(retired)
        })
    }

    /// Idempotent: a missing key is not an error (S3 semantics).
    pub fn delete_object(&self, bucket: &str, key: &str, now: u64) -> Result<Retired> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let k = obj_key(bucket, key);
            w.open_table(OBJECTS)?.remove(k.as_slice())?;
            let old = w
                .open_table(MANIFESTS)?
                .remove(k.as_slice())?
                .map(|v| v.value().to_vec());
            let mut retired = Vec::new();
            if let Some(old) = old {
                retire_manifest(w, &old, now, &mut retired)?;
            }
            Ok(retired)
        })
    }

    /// ListObjectsV2 over the index — see [`crate::ObjectStore::list_v2`] for semantics.
    /// A range scan from `max(prefix, start_after)`: after emitting folder `f` the scan
    /// seeks to `f ++ 0xFF`, past every key under it (no UTF-8 key contains `0xFF`), so a
    /// folder with a million keys costs one step. Reads at most `max_keys + 1` rows.
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
                let meta: ObjectMeta = serde_json::from_slice(v.value())
                    .map_err(|_| ObjectError::CorruptMeta(key.to_string()))?;
                entries.push((key.to_string(), Some(meta)));
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

    /// Create the upload row; with `keep_existing`, an existing row is left as is
    /// (migration).
    pub fn create_upload(
        &self,
        bucket: &str,
        upload_id: &str,
        info: &UploadInfo,
        keep_existing: bool,
    ) -> Result<()> {
        self.write(|w| {
            require_bucket(w, bucket)?;
            let mut t = w.open_table(UPLOADS)?;
            let k = upload_key(bucket, upload_id);
            if !(keep_existing && t.get(k.as_slice())?.is_some()) {
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
    /// re-upload a part number).
    pub fn commit_part(
        &self,
        bucket: &str,
        upload_id: &str,
        part: u32,
        row: &PartRow,
        now: u64,
    ) -> Result<Retired> {
        self.write(|w| {
            require_upload(w, bucket, upload_id)?;
            take_pending(w, std::iter::once(row.segment.as_str()))?;
            let old = w
                .open_table(PARTS)?
                .insert(part_key(upload_id, part).as_slice(), json(row).as_slice())?
                .map(|v| v.value().to_vec());
            let mut retired = Vec::new();
            if let Some(old) = old
                && let Ok(old) = serde_json::from_slice::<PartRow>(&old)
            {
                w.open_table(GARBAGE)?.insert(old.segment.as_str(), now)?;
                retired.push(old.segment);
            }
            Ok(retired)
        })
    }

    /// Complete an upload: the object's segments ARE the listed parts' segments, in
    /// order — no byte is copied. As in S3, every listed part but the last must be at
    /// least [`MIN_PART_SIZE`]; a refused complete changes nothing, so the client can
    /// retry. Parts uploaded but not listed are retired. The etag is S3's
    /// `md5(concat of part md5s)-<count>`.
    pub fn complete_upload(
        &self,
        bucket: &str,
        key: &str,
        upload_id: &str,
        part_numbers: &[u32],
        now: u64,
    ) -> Result<(ObjectMeta, Retired)> {
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
                return Err(ObjectError::InvalidPartOrder);
            }
            let (lo, hi) = upload_part_range(upload_id);
            let mut staged: BTreeMap<u32, PartRow> = BTreeMap::new();
            for item in w.open_table(PARTS)?.range(lo.as_slice()..hi.as_slice())? {
                let (k, v) = item?;
                let Ok(pn) = <[u8; 4]>::try_from(&k.value()[lo.len()..]) else {
                    continue;
                };
                let row: PartRow = serde_json::from_slice(v.value())
                    .map_err(|_| ObjectError::CorruptMeta(upload_id.to_string()))?;
                staged.insert(u32::from_be_bytes(pn), row);
            }
            let mut concat = Md5::new();
            let mut segments = Vec::with_capacity(part_numbers.len());
            for (i, &pn) in part_numbers.iter().enumerate() {
                let Some(row) = staged.remove(&pn) else {
                    return Err(ObjectError::InvalidArgument(format!("missing part {pn}")));
                };
                if row.size < MIN_PART_SIZE && i + 1 < part_numbers.len() {
                    return Err(ObjectError::EntityTooSmall(pn));
                }
                concat.update(unhex(&row.md5));
                segments.push(SegRef {
                    id: row.segment,
                    size: row.size,
                });
            }
            // The listed parts now belong to the object; dropping the upload retires the
            // ones uploaded but not listed.
            let mut parts = w.open_table(PARTS)?;
            for &pn in part_numbers {
                parts.remove(part_key(upload_id, pn).as_slice())?;
            }
            drop(parts);
            let mut retired = Vec::new();
            drop_upload(w, bucket, upload_id, now, &mut retired)?;
            let meta = ObjectMeta {
                key: key.to_string(),
                size: segments.iter().map(|s| s.size).sum(),
                etag: format!("{}-{}", hex(&concat.finalize()), part_numbers.len()),
                content_type: info.content_type,
                last_modified: now,
                cache_control: info.cache_control,
            };
            let k = obj_key(bucket, key);
            w.open_table(OBJECTS)?
                .insert(k.as_slice(), json(&meta).as_slice())?;
            let old = w
                .open_table(MANIFESTS)?
                .insert(k.as_slice(), json(&segments).as_slice())?
                .map(|v| v.value().to_vec());
            if let Some(old) = old {
                retire_manifest(w, &old, now, &mut retired)?;
            }
            Ok((meta, retired))
        })
    }

    pub fn abort_upload(&self, bucket: &str, upload_id: &str, now: u64) -> Result<Retired> {
        self.write(|w| {
            require_upload(w, bucket, upload_id)?;
            let mut retired = Vec::new();
            drop_upload(w, bucket, upload_id, now, &mut retired)?;
            Ok(retired)
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

    /// Abort up to `limit` uploads initiated at or before `threshold`; returns how many
    /// and the segments that retired.
    pub fn abort_uploads_before(
        &self,
        threshold: u64,
        now: u64,
        limit: usize,
    ) -> Result<(usize, Retired)> {
        self.write(|w| {
            let mut stale = Vec::new();
            for item in w.open_table(UPLOADS)?.iter()? {
                let (k, v) = item?;
                let initiated =
                    serde_json::from_slice::<UploadInfo>(v.value()).map_or(0, |i| i.initiated);
                if initiated <= threshold {
                    stale.push(k.value().to_vec());
                    if stale.len() == limit {
                        break;
                    }
                }
            }
            let mut retired = Vec::new();
            for k in &stale {
                let Some(nul) = k.iter().position(|&b| b == 0) else {
                    continue;
                };
                let bucket = String::from_utf8_lossy(&k[..nul]).into_owned();
                let upload_id = String::from_utf8_lossy(&k[nul + 1..]).into_owned();
                drop_upload(w, &bucket, &upload_id, now, &mut retired)?;
            }
            Ok((stale.len(), retired))
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
/// already judged the write dead and may be deleting its bytes: refuse rather than
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

fn retire_manifest(
    w: &WriteTransaction,
    manifest: &[u8],
    now: u64,
    out: &mut Retired,
) -> Result<()> {
    let Ok(segments) = serde_json::from_slice::<Vec<SegRef>>(manifest) else {
        return Ok(()); // unreadable manifest: nothing we can name to reclaim
    };
    let mut g = w.open_table(GARBAGE)?;
    for s in segments {
        g.insert(s.id.as_str(), now)?;
        out.push(s.id);
    }
    Ok(())
}

/// Remove an upload and every part still staged under it, retiring their segments.
fn drop_upload(
    w: &WriteTransaction,
    bucket: &str,
    upload_id: &str,
    now: u64,
    out: &mut Retired,
) -> Result<()> {
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
            g.insert(seg.as_str(), now)?;
            out.push(seg);
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

fn json<T: Serialize + ?Sized>(v: &T) -> Vec<u8> {
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
