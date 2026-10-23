//! Migration from the layout-1 store (the directory tree WAS the index: one subdirectory
//! per bucket, an object = `<stem>` bytes + `<stem>.meta` JSON sidecar, multipart staging
//! under `<bucket>/.uploads/<id>/`, CORS under `.cors/<bucket>.json`) into the layout-2
//! index + segments.
//!
//! Runs whenever a root holds layout-1 content — not only once: an older binary run
//! after a migration (a rollback) writes layout-1 bucket directories again, and those
//! writes must not be stranded. Invariants that make that safe:
//!
//! - **A bucket directory is hidden before it is migrated**: renamed to
//!   `.migrating-<bucket>`, which no layout-1 binary lists. An older binary therefore
//!   only ever sees buckets nobody has started migrating, so it can neither write an
//!   object this run already moved nor delete one and have it come back.
//! - **Legacy content always wins.** It is never older than the index: a plain bucket
//!   directory was written by an older binary after anything the index holds for it,
//!   and a `.migrating-` directory is finished before the store serves a request. So
//!   rows are committed unconditionally, replacing (and retiring) what is there.
//! - **Crash-safe at every step**: segment ids are recorded pending before their hard
//!   links exist, a batch's rows commit in one transaction, and legacy files are unlinked
//!   only after their rows committed. A re-run repeats at most one batch.
//!
//! An object that can't be migrated (a corrupt sidecar — already unreadable through the
//! API) is never deleted: its bucket's leftovers move to `.unmigrated/`.

use crate::index::{Index, LAYOUT_V2, ObjectRow, PartRow, SegRef};
use crate::segments::{LocalSegments, sync_dir_blocking};
use crate::store::{
    ObjectError, ObjectMeta, UploadInfo, new_id, now_secs, validate_bucket, validate_key,
};
use sha2::{Digest, Sha256};
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

type Result<T> = std::result::Result<T, ObjectError>;

const META_SUFFIX: &str = ".meta";
const MIGRATING: &str = ".migrating-";
const UNMIGRATED: &str = ".unmigrated";

/// Objects committed per index transaction (one fsync per batch, not per object).
const BATCH: usize = 512;

/// Whether `root` holds anything layout 1 wrote: a bucket directory (any non-dot
/// directory), a half-migrated one, or no layout-2 stamp yet.
pub(crate) fn needs_migration(root: &Path, index: &Index) -> Result<bool> {
    if index.layout()? < LAYOUT_V2 {
        return Ok(true);
    }
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if entry.file_type()?.is_dir() && (!name.starts_with('.') || name.starts_with(MIGRATING)) {
            return Ok(true);
        }
    }
    Ok(false)
}

/// Migrate every layout-1 bucket under `root`, then stamp layout 2.
pub(crate) fn migrate(root: &Path, index: &Index, segs: &LocalSegments) -> Result<()> {
    let mut moved = 0usize;
    // Finish what an interrupted run already hid, before hiding anything new: a plain
    // directory of the same name (written by an older binary since) can only be renamed
    // once its `.migrating-` twin is gone.
    for (bucket, dir) in buckets(root, true)? {
        moved += migrate_bucket(root, &bucket, &dir, index, segs)?;
    }
    for (bucket, dir) in buckets(root, false)? {
        let hidden = root.join(format!("{MIGRATING}{bucket}"));
        std::fs::rename(&dir, &hidden)?;
        sync_dir_blocking(root)?;
        moved += migrate_bucket(root, &bucket, &hidden, index, segs)?;
    }
    let _ = std::fs::remove_dir(root.join(".cors")); // only once every sidecar moved
    index.set_layout(LAYOUT_V2)?;
    if moved > 0 {
        tracing::info!(root = %root.display(), moved, "object-store: migrated layout-1 objects into the index");
    }
    Ok(())
}

/// `(bucket, dir)` for each plain bucket directory, or with `hidden` each
/// `.migrating-<bucket>` one. Names that aren't valid buckets are left alone.
fn buckets(root: &Path, hidden: bool) -> Result<Vec<(String, PathBuf)>> {
    let mut out = Vec::new();
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        let bucket = match (hidden, name.strip_prefix(MIGRATING)) {
            (true, Some(b)) => b.to_string(),
            (false, None) if !name.starts_with('.') => name,
            _ => continue,
        };
        if validate_bucket(&bucket).is_ok() {
            out.push((bucket, entry.path()));
        }
    }
    out.sort();
    Ok(out)
}

/// Migrate one (hidden) bucket directory; returns how many objects moved.
fn migrate_bucket(
    root: &Path,
    bucket: &str,
    dir: &Path,
    index: &Index,
    segs: &LocalSegments,
) -> Result<usize> {
    index.ensure_bucket(bucket, mtime(dir))?;
    let cors = root.join(".cors").join(format!("{bucket}.json"));
    if let Ok(bytes) = std::fs::read(&cors)
        && let Ok(cfg) = serde_json::from_slice(&bytes)
    {
        index.set_cors(bucket, Some(cfg))?;
    }

    let mut objects = Vec::new();
    let mut unreadable = 0usize;
    for entry in std::fs::read_dir(dir)? {
        let name = entry?.file_name().to_string_lossy().into_owned();
        if let Some(stem) = name.strip_suffix(META_SUFFIX) {
            match read_legacy(dir, stem)? {
                Legacy::Object(meta, size) => objects.push((stem.to_string(), meta, size)),
                Legacy::Gone => {}
                Legacy::Unreadable => unreadable += 1,
            }
        }
    }
    let moved = objects.len();
    for batch in objects.chunks(BATCH) {
        let ids: Vec<String> = batch.iter().map(|_| new_id()).collect();
        let now = now_secs();
        index.add_pending(&ids, now)?;
        let mut fans = BTreeSet::new();
        let mut rows = Vec::with_capacity(batch.len());
        for ((stem, meta, size), id) in batch.iter().zip(&ids) {
            fans.insert(segs.link_blocking(id, &dir.join(stem))?);
            rows.push(ObjectRow {
                meta: ObjectMeta {
                    size: *size,
                    ..meta.clone()
                },
                segments: vec![SegRef {
                    id: id.clone(),
                    size: *size,
                }],
            });
        }
        for fan in &fans {
            sync_dir_blocking(fan)?;
        }
        // Whatever these replace (a previous interrupted run's links, or rows the
        // older binary's writes supersede) is garbage the boot sweep reclaims.
        index.commit_objects(bucket, &rows, now)?;
        for (stem, _, _) in batch {
            std::fs::remove_file(dir.join(stem))?;
            std::fs::remove_file(dir.join(format!("{stem}{META_SUFFIX}")))?;
        }
    }

    if let Ok(rd) = std::fs::read_dir(dir.join(".uploads")) {
        for up in rd {
            let up = up?;
            if up.file_type()?.is_dir() {
                migrate_upload(&up.path(), bucket, index, segs)?;
            }
        }
    }

    // What is left is temp files and bytes without a sidecar (unreachable through the
    // API already) — unless some object couldn't be read; then keep it all, aside.
    if unreadable == 0 {
        std::fs::remove_dir_all(dir)?;
    } else {
        let aside = root.join(UNMIGRATED);
        std::fs::create_dir_all(&aside)?;
        std::fs::rename(dir, aside.join(format!("{bucket}.{}", new_id())))?;
        tracing::warn!(root = %root.display(), bucket, unreadable,
            "object-store migration: unreadable legacy objects set aside in .unmigrated/");
    }
    let _ = std::fs::remove_file(&cors);
    Ok(moved)
}

enum Legacy {
    Object(ObjectMeta, u64),
    /// A sidecar whose bytes are missing (the old engine answered it with an IO error):
    /// nothing to keep, sidecar removed.
    Gone,
    Unreadable,
}

fn read_legacy(dir: &Path, stem: &str) -> Result<Legacy> {
    let sidecar = dir.join(format!("{stem}{META_SUFFIX}"));
    let Ok(meta) = std::fs::read(&sidecar)
        .map_err(|_| ())
        .and_then(|raw| serde_json::from_slice::<ObjectMeta>(&raw).map_err(|_| ()))
    else {
        return Ok(Legacy::Unreadable);
    };
    // Only a sidecar under its own key's name was ever served (see the old `locate`).
    if validate_key(&meta.key).is_err() || object_stem(&meta.key) != stem {
        return Ok(Legacy::Unreadable);
    }
    match std::fs::metadata(dir.join(stem)) {
        Ok(m) => Ok(Legacy::Object(meta, m.len())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_file(&sidecar)?;
            Ok(Legacy::Gone)
        }
        Err(e) => Err(e.into()),
    }
}

/// Migrate one in-flight multipart upload (`info.json`, `part-N`, `part-N.md5`), so an
/// upload spanning the deploy that runs this still completes.
fn migrate_upload(sdir: &Path, bucket: &str, index: &Index, segs: &LocalSegments) -> Result<()> {
    let upload_id = sdir
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let info = std::fs::read(sdir.join("info.json"))
        .ok()
        .and_then(|b| serde_json::from_slice::<UploadInfo>(&b).ok());
    let hexid = !upload_id.is_empty() && upload_id.bytes().all(|b| b.is_ascii_hexdigit());
    if let (Some(mut info), true) = (info, hexid) {
        if info.initiated == 0 {
            info.initiated = mtime(&sdir.join("info.json"));
        }
        index.create_upload(bucket, &upload_id, &info, true)?;
        for f in std::fs::read_dir(sdir)? {
            let f = f?;
            let fname = f.file_name().to_string_lossy().into_owned();
            let Some(pn) = fname
                .strip_prefix("part-")
                .and_then(|n| n.parse::<u32>().ok())
                .filter(|n| (1..=10_000).contains(n))
            else {
                continue;
            };
            let Ok(md5) = std::fs::read(sdir.join(format!("part-{pn}.md5"))) else {
                continue; // the part's rename landed but its digest didn't: never acknowledged
            };
            let size = f.metadata()?.len();
            let id = new_id();
            let now = now_secs();
            index.add_pending(std::slice::from_ref(&id), now)?;
            let fan = segs.link_blocking(&id, &f.path())?;
            sync_dir_blocking(&fan)?;
            let row = PartRow {
                segment: id,
                size,
                md5: hex(&md5),
            };
            index.commit_part(bucket, &upload_id, pn, &row, now)?;
        }
    }
    // Unreadable staging was unusable before too (complete needs info.json).
    std::fs::remove_dir_all(sdir)?;
    Ok(())
}

fn mtime(p: &Path) -> u64 {
    std::fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| t.duration_since(UNIX_EPOCH).ok())
        .map_or(0, |d| d.as_secs())
}

// ---- the layout-1 file-name scheme (read side only) -------------------------

const HEX_NAME_MAX_KEY: usize = (255 - META_SUFFIX.len()) / 2;
const B64_NAME_MAX_KEY: usize = 186;
const HASH_NAME_HEAD: usize = 153;

/// The layout-1 file-name stem for `key`: `hex(key)` up to 125 bytes, `b-<b64(key)>` up
/// to 186, `k-<b64(sha256(key))>.<b64(first 153 bytes)>` up to 1024.
pub(crate) fn object_stem(key: &str) -> String {
    let b = key.as_bytes();
    if b.len() <= HEX_NAME_MAX_KEY {
        hex(b)
    } else if b.len() <= B64_NAME_MAX_KEY {
        format!("b-{}", b64(b))
    } else {
        format!(
            "k-{}.{}",
            b64(&Sha256::digest(b)),
            b64(&b[..HASH_NAME_HEAD])
        )
    }
}

const B64_ALPHABET: &[u8; 64] = b"-0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ_abcdefghijklmnopqrstuvwxyz";

fn b64(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let n =
            chunk.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b)) << (8 * (3 - chunk.len()));
        for i in 0..=chunk.len() {
            s.push(B64_ALPHABET[(n >> (18 - 6 * i)) as usize & 63] as char);
        }
    }
    s
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
