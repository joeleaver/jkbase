//! One-way migration from the layout-1 store (the directory tree WAS the index: one
//! subdirectory per bucket, an object = `<stem>` bytes + `<stem>.meta` JSON sidecar,
//! multipart staging under `<bucket>/.uploads/<id>/`, CORS under `.cors/<bucket>.json`)
//! into the layout-2 index + segments.
//!
//! Crash-safe and idempotent, so an interrupted run simply runs again: per object the
//! bytes are hard-linked into a segment whose id is recorded pending FIRST, the index row
//! is committed only if the key isn't already there (a previous run got that far), and
//! only then are the legacy files unlinked. A crash leaves at worst a pending segment the
//! sweeper reclaims. Roll-forward only: an older binary can't read a migrated store.

use crate::index::{Index, LAYOUT_V2, ObjectRow, PartRow, SegRef};
use crate::segments::LocalSegments;
use crate::store::{
    ObjectError, ObjectMeta, UploadInfo, new_id, now_secs, validate_bucket, validate_key,
};
use sha2::{Digest, Sha256};
use std::path::Path;
use std::time::UNIX_EPOCH;

type Result<T> = std::result::Result<T, ObjectError>;

const META_SUFFIX: &str = ".meta";

/// Migrate the store at `root` into `index` + `segs`, then stamp layout 2. Anything that
/// could not be migrated (a corrupt sidecar — already unreadable through the API) is left
/// where it is, with its bucket directory, and logged; it is never deleted.
pub(crate) fn migrate(root: &Path, index: &Index, segs: &LocalSegments) -> Result<()> {
    let mut moved = 0usize;
    let mut skipped = 0usize;
    for entry in std::fs::read_dir(root)? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        if name.starts_with('.') || !entry.file_type()?.is_dir() || validate_bucket(&name).is_err()
        {
            continue;
        }
        let dir = entry.path();
        index.ensure_bucket(&name, mtime(&dir))?;
        if let Ok(bytes) = std::fs::read(root.join(".cors").join(format!("{name}.json")))
            && let Ok(cfg) = serde_json::from_slice(&bytes)
            && index.get_cors(&name)?.is_none()
        {
            index.set_cors(&name, Some(cfg))?;
        }

        let mut left = 0usize;
        for obj in std::fs::read_dir(&dir)? {
            let obj = obj?;
            let fname = obj.file_name().to_string_lossy().into_owned();
            if let Some(stem) = fname.strip_suffix(META_SUFFIX) {
                if migrate_object(&dir, &name, stem, index, segs)? {
                    moved += 1;
                } else {
                    left += 1;
                }
            }
        }
        let uploads = dir.join(".uploads");
        if let Ok(rd) = std::fs::read_dir(&uploads) {
            for up in rd {
                let up = up?;
                if up.file_type()?.is_dir() {
                    migrate_upload(&up.path(), &name, index, segs)?;
                }
            }
        }
        // Everything still here is a temp file or bytes without a sidecar — unreachable
        // through the API already — unless an object refused to migrate.
        if left == 0 {
            std::fs::remove_dir_all(&dir)?;
        } else {
            skipped += left;
            tracing::warn!(root = %root.display(), bucket = %name, left,
                "object-store migration: unreadable legacy objects left in place");
        }
    }
    let _ = std::fs::remove_dir_all(root.join(".cors"));
    index.set_layout(LAYOUT_V2)?;
    if moved > 0 || skipped > 0 {
        tracing::info!(root = %root.display(), moved, skipped, "object-store: migrated to the index layout");
    }
    Ok(())
}

/// Migrate one `<stem>` + `<stem>.meta` pair. `Ok(false)` = left in place (unreadable).
fn migrate_object(
    dir: &Path,
    bucket: &str,
    stem: &str,
    index: &Index,
    segs: &LocalSegments,
) -> Result<bool> {
    let sidecar = dir.join(format!("{stem}{META_SUFFIX}"));
    let bytes_path = dir.join(stem);
    let Ok(raw) = std::fs::read(&sidecar) else {
        return Ok(false);
    };
    let Ok(mut meta) = serde_json::from_slice::<ObjectMeta>(&raw) else {
        return Ok(false);
    };
    // Only a sidecar under its own key's name was ever served (see the old `locate`).
    if validate_key(&meta.key).is_err() || object_stem(&meta.key) != stem {
        return Ok(false);
    }
    let size = match std::fs::metadata(&bytes_path) {
        Ok(m) => m.len(),
        // Sidecar without bytes: the old engine answered this with an IO error. Nothing
        // to keep.
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            std::fs::remove_file(&sidecar)?;
            return Ok(true);
        }
        Err(e) => return Err(e.into()),
    };
    meta.size = size;
    let id = new_id();
    let now = now_secs();
    index.add_pending(&id, now)?;
    segs.link_blocking(&id, &bytes_path)?;
    let row = ObjectRow {
        meta,
        segments: vec![SegRef {
            id: id.clone(),
            size,
        }],
    };
    if !index.commit_object(bucket, &row, now, true)? {
        index.discard_pending(&[id], now)?; // an earlier, interrupted run already moved it
    }
    std::fs::remove_file(&bytes_path)?;
    std::fs::remove_file(&sidecar)?;
    Ok(true)
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
        index.ensure_upload(bucket, &upload_id, &info)?;
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
            index.add_pending(&id, now)?;
            segs.link_blocking(&id, &f.path())?;
            let row = PartRow {
                segment: id.clone(),
                size,
                md5: hex(&md5),
            };
            if !index.commit_part(bucket, &upload_id, pn, &row, now, true)? {
                index.discard_pending(&[id], now)?;
            }
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
