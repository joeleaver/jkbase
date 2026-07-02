//! Platform-owned managed-DB backup blob store ([RB4]).
//!
//! A plain per-project filesystem layout under `{data_dir}/db-backups/{project_id}/{backup_id}.tar`.
//! This is deliberately NOT a tenant `ObjectStore`: it is never wired into any HTTP router
//! (no SigV4/console/proxy surface), it is off tenant quota by construction (never summed by
//! `project_storage_bytes`), and a tenant can neither address nor delete a snapshot through the
//! object-store path. The host stores/serves the tar as OPAQUE bytes — it never mounts or parses
//! a guest filesystem (the tar came from the guest, but is only ever written whole and read whole,
//! then handed back to the SAME guest to untar).
//!
//! Per-project layout makes teardown GC a single `remove_dir_all` ([RB11]); the hex-keyed
//! `ObjectStore` layout would defeat that.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

/// A validated project id path component: non-empty, ≤63, `[a-z0-9-]` only — matches the
/// object-store service's `is_valid_project_id`, so a malformed id can never escape the root.
fn is_valid_project_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 63
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
}

/// A backup id is `bkp_<ms>_<hex>` — only `[a-z0-9_]`, so it is a safe filename component.
fn is_valid_backup_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 128
        && id
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}

pub struct BackupStore {
    root: PathBuf,
}

/// A streamed-but-not-yet-committed backup on disk. Dropping it without `commit` leaves the
/// `.tmp` behind for the next boot's sweep; call `discard` to remove it promptly.
pub struct StagedBackup {
    tmp: PathBuf,
    final_path: PathBuf,
    pub size_bytes: u64,
}

impl BackupStore {
    pub fn new(data_dir: &Path) -> Self {
        Self {
            root: data_dir.join("db-backups"),
        }
    }

    fn project_dir(&self, project_id: &str) -> Result<PathBuf> {
        if !is_valid_project_id(project_id) {
            anyhow::bail!("invalid project id for backup store");
        }
        Ok(self.root.join(project_id))
    }

    fn object_path(&self, project_id: &str, backup_id: &str) -> Result<PathBuf> {
        if !is_valid_backup_id(backup_id) {
            anyhow::bail!("invalid backup id");
        }
        Ok(self
            .project_dir(project_id)?
            .join(format!("{backup_id}.tar")))
    }

    /// Stream a backup tar off `reader` into a temp file next to its final path (same dir → the
    /// later rename is atomic), capping at `max_bytes` ([RB3]). Returns a [`StagedBackup`] the
    /// caller validates (see [`validate_and_summarize`]) then `commit`s. Never buffers in memory.
    pub async fn stage<R>(
        &self,
        project_id: &str,
        backup_id: &str,
        reader: &mut R,
        max_bytes: u64,
    ) -> Result<StagedBackup>
    where
        R: tokio::io::AsyncRead + Unpin,
    {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let dir = self.project_dir(project_id)?;
        tokio::fs::create_dir_all(&dir)
            .await
            .context("create backup project dir")?;
        let final_path = self.object_path(project_id, backup_id)?;
        let tmp = dir.join(format!(".{backup_id}.tar.tmp"));
        // Stream to the tmp file; on ANY error remove the tmp so a failed/aborted pull can't leak
        // a partial multi-GiB file on the off-quota host disk (finding: .tmp leak).
        // Bound the whole pull's duration so a hostile guest can't slow-drip a stream past the
        // single-flight/stale window and leave an orphaned off-quota blob (adversarial-review
        // residual). Comfortably above a legit multi-GiB backup over the fast VM→host link, well
        // below Store::BACKUP_STALE_MS.
        let deadline = tokio::time::Instant::now() + STAGE_MAX_DURATION;
        let stream = async {
            let mut f = tokio::fs::File::create(&tmp)
                .await
                .context("create backup tmp")?;
            let mut buf = vec![0u8; 64 * 1024];
            let mut size: u64 = 0;
            loop {
                let n = tokio::time::timeout_at(deadline, reader.read(&mut buf))
                    .await
                    .map_err(|_| anyhow::anyhow!("backup stream stalled / exceeded time budget"))?
                    .context("read backup stream")?;
                if n == 0 {
                    break;
                }
                size += n as u64;
                if size > max_bytes {
                    anyhow::bail!("backup exceeds {max_bytes} bytes");
                }
                f.write_all(&buf[..n]).await.context("write backup tmp")?;
            }
            f.flush().await.context("flush backup tmp")?;
            Ok::<u64, anyhow::Error>(size)
        };
        match stream.await {
            Ok(size) => Ok(StagedBackup {
                tmp,
                final_path,
                size_bytes: size,
            }),
            Err(e) => {
                let _ = tokio::fs::remove_file(&tmp).await;
                Err(e)
            }
        }
    }

    /// Validate a staged tar ([RB8]) off the async thread and return its manifest summary.
    /// Errs (⇒ discard) if the tar is truncated / has no `MANIFEST.json`.
    pub async fn validate(&self, staged: &StagedBackup) -> Result<String> {
        let tmp = staged.tmp.clone();
        tokio::task::spawn_blocking(move || validate_and_summarize(&tmp))
            .await
            .context("backup validation task join")?
    }

    /// Atomically publish a staged backup (rename tmp → final).
    pub async fn commit(&self, staged: StagedBackup) -> Result<()> {
        tokio::fs::rename(&staged.tmp, &staged.final_path)
            .await
            .context("publish backup")
    }

    /// Remove a staged-but-rejected backup's temp file.
    pub async fn discard(&self, staged: StagedBackup) {
        let _ = tokio::fs::remove_file(&staged.tmp).await;
    }

    /// Open a committed backup tar for reading (restore).
    pub async fn open_read(&self, project_id: &str, backup_id: &str) -> Result<tokio::fs::File> {
        let path = self.object_path(project_id, backup_id)?;
        tokio::fs::File::open(&path)
            .await
            .with_context(|| format!("open backup {}", path.display()))
    }

    /// Delete one committed backup (retention / on-demand prune).
    pub async fn delete(&self, project_id: &str, backup_id: &str) -> Result<()> {
        let path = self.object_path(project_id, backup_id)?;
        match tokio::fs::remove_file(&path).await {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(e) => Err(e).context("delete backup"),
        }
    }
}

/// A real rhypedb backup MANIFEST.json is a few KB of metadata. Cap the read hard so a hostile
/// guest can't declare a multi-GiB MANIFEST entry and OOM the shared host process — the tar bytes
/// are wholly guest-controlled (the pull relays loopback:4200 opaquely), so this is on the
/// adversarial path ([RB3]).
const MAX_MANIFEST_BYTES: u64 = 4 * 1024 * 1024;

/// Total wall-clock budget for streaming one backup tar off the agent. Bounds a slow-drip /
/// stalled pull so it can't outlive the single-flight window (< `Store::BACKUP_STALE_MS` = 30m)
/// and orphan a committed off-quota blob.
const STAGE_MAX_DURATION: std::time::Duration = std::time::Duration::from_secs(15 * 60);

/// A plain, in-directory filename: non-empty, no path separators, not `.`/`..`, not absolute.
/// Mirrors rhypedb's `is_safe_filename` (restore.rs) so the host rejects a manifest that lists a
/// traversal name (`../x.sst`) — otherwise the host's basename-normalized presence check would
/// pass a snapshot that rhypedb's own restore then refuses, bricking the DB on restore.
fn is_safe_manifest_name(name: &str) -> bool {
    !name.is_empty()
        && name != "."
        && name != ".."
        && !name.contains('/')
        && !name.contains('\\')
        && !std::path::Path::new(name).is_absolute()
}

/// Read exactly `buf.len()` bytes, or fewer at EOF. Returns the count read.
fn read_full(f: &mut impl std::io::Read, buf: &mut [u8]) -> std::io::Result<usize> {
    let mut got = 0;
    while got < buf.len() {
        match f.read(&mut buf[got..])? {
            0 => break,
            k => got += k,
        }
    }
    Ok(got)
}

/// Parse a 12-byte tar size field: octal ASCII, or GNU base-256 (high bit of byte 0 set).
fn parse_tar_size(field: &[u8]) -> Result<u64> {
    if field.first().is_some_and(|b| b & 0x80 != 0) {
        let mut v: u128 = (field[0] & 0x7f) as u128;
        for &b in &field[1..] {
            v = (v << 8) | b as u128;
        }
        u64::try_from(v).map_err(|_| anyhow::anyhow!("tar size overflow"))
    } else {
        let s = std::str::from_utf8(field)
            .unwrap_or("")
            .trim_matches(|c| c == '\0' || c == ' ');
        if s.is_empty() {
            return Ok(0);
        }
        u64::from_str_radix(s, 8).map_err(|_| anyhow::anyhow!("bad tar size field"))
    }
}

/// Bounded-memory guard against a host-OOM in the tar PARSER itself ([RB3]). The `tar` crate reads
/// GNU long-name (`L`), long-link (`K`), and PAX extension (`x`/`g`) entry bodies FULLY into RAM
/// before yielding an entry — before any per-entry cap in [`validate_and_summarize`] runs — so a
/// hostile guest could declare a multi-GiB such header and OOM the shared host process. A
/// legitimate rhypedb backup contains ONLY regular files + directories with short ustar names, so
/// we pre-walk the 512-byte headers (seeking over data, O(1) memory) and reject any tar carrying
/// an unsupported entry type before it ever reaches `tar::Archive`.
fn reject_unsafe_tar_headers(tar_path: &Path) -> Result<()> {
    use std::io::{Seek, SeekFrom};
    // A legit rhypedb backup has at most a few thousand entries; cap the scan far above that so a
    // pathological all-headers tar (millions of zero-size entries) can't burn CPU here.
    const MAX_TAR_ENTRIES: u64 = 1_000_000;
    let mut f = std::io::BufReader::new(
        std::fs::File::open(tar_path).context("open backup for header scan")?,
    );
    let mut hdr = [0u8; 512];
    let mut zero_blocks = 0;
    let mut entries = 0u64;
    loop {
        entries += 1;
        if entries > MAX_TAR_ENTRIES {
            anyhow::bail!("backup tar has too many entries (rejecting)");
        }
        let n = read_full(&mut f, &mut hdr).context("read tar header")?;
        if n == 0 {
            break; // EOF (no end-of-archive marker — validate_and_summarize's drain catches it)
        }
        if n < 512 {
            anyhow::bail!("truncated tar header");
        }
        if hdr.iter().all(|&b| b == 0) {
            zero_blocks += 1;
            if zero_blocks == 2 {
                break; // end-of-archive
            }
            continue;
        }
        zero_blocks = 0;
        // typeflag @156. Allow regular file ('0'/NUL) + directory ('5'); reject L/K/x/g and any
        // other extension whose body the tar crate would buffer unbounded.
        match hdr[156] {
            b'0' | 0u8 | b'5' => {}
            other => anyhow::bail!(
                "backup tar has an unsupported entry type {other:#x} (rejecting to bound host memory)"
            ),
        }
        let size = parse_tar_size(&hdr[124..136])?;
        // Clamp to i64::MAX so a malicious declared size can't wrap `as i64` negative and seek
        // backwards into a loop; a seek past EOF just makes the next read return 0 → break.
        let data = i64::try_from(size.div_ceil(512).saturating_mul(512)).unwrap_or(i64::MAX);
        f.seek(SeekFrom::Current(data))
            .context("seek past tar entry data")?;
    }
    Ok(())
}

/// Validate a completed backup tar and extract a one-line summary from its `MANIFEST.json`
/// ([RB8]). Sync (tar is a blocking reader) — run under `spawn_blocking`.
///
/// Truncation-safe: `MANIFEST.json` is NOT reliably the last entry in the tar STREAM (rhypedb
/// builds it with `append_dir_all`, i.e. unsorted `readdir` order — it is only written last to
/// the on-disk temp dir for fsync durability), so its mere presence proves nothing. We therefore
/// (1) iterate EVERY entry to the tar's end-of-archive marker, draining each entry's body so a
/// mid-stream truncation surfaces as a hard error rather than a silent early stop, (2) cap the
/// MANIFEST read so a giant manifest can't OOM the host, and (3) cross-check that every
/// manifest-listed load-bearing file (SSTs + `wal.log` + `schema.rhype`) is actually present.
/// A truncated/incomplete tar therefore fails validation and is never committed/restored.
pub fn validate_and_summarize(tar_path: &Path) -> Result<String> {
    use std::io::Read;
    // Bound the tar PARSER's memory before handing the guest-controlled tar to `tar::Archive`.
    reject_unsafe_tar_headers(tar_path)?;
    let f = std::fs::File::open(tar_path).context("open backup for validation")?;
    let mut ar = tar::Archive::new(f);
    let mut manifest: Option<serde_json::Value> = None;
    // Basenames of every fully-read entry (rhypedb entries: `sst/<n>.sst`, `wal.log`,
    // `schema.rhype`, `hnsw_*.bin`, `MANIFEST.json` — all with unique basenames).
    let mut present: std::collections::HashSet<String> = std::collections::HashSet::new();
    for entry in ar.entries().context("read backup entries")? {
        // A truncation mid-entry / mid-header surfaces here or in the drain below as an Err —
        // exactly the end-of-archive validation [RB8] requires.
        let mut entry = entry.context("read backup entry (truncated?)")?;
        let path = entry.path().context("backup entry path")?;
        let base = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|s| s.to_string());
        if base.as_deref() == Some("MANIFEST.json") && manifest.is_none() {
            if entry.header().size().unwrap_or(u64::MAX) > MAX_MANIFEST_BYTES {
                anyhow::bail!("backup MANIFEST.json is implausibly large (rejecting)");
            }
            let mut b = Vec::new();
            entry
                .by_ref()
                .take(MAX_MANIFEST_BYTES)
                .read_to_end(&mut b)
                .context("read MANIFEST.json")?;
            manifest = Some(serde_json::from_slice(&b).context("parse backup MANIFEST.json")?);
        } else {
            // Drain the body to advance to the next header AND force the tar reader to detect a
            // truncated final entry. Discarded (never buffered).
            std::io::copy(&mut entry, &mut std::io::sink()).context("read backup entry body")?;
        }
        if let Some(b) = base {
            present.insert(b);
        }
    }
    let v = manifest.ok_or_else(|| anyhow::anyhow!("backup is incomplete: no MANIFEST.json"))?;
    // Cross-check completeness: every load-bearing file the manifest vouches for must be present
    // (a clean end-of-archive that dropped trailing entries would still be caught here).
    let mut missing: Vec<String> = Vec::new();
    if let Some(ssts) = v.get("ssts").and_then(|s| s.as_array()) {
        for s in ssts.iter().filter_map(|x| x.as_str()) {
            // Reject a traversal name outright — rhypedb's restore refuses it, so a snapshot our
            // basename check would "pass" here would brick the DB on restore.
            if !is_safe_manifest_name(s) {
                anyhow::bail!("backup MANIFEST.json lists an unsafe sst filename: {s:?}");
            }
            if !present.contains(s) {
                missing.push(format!("sst/{s}"));
            }
        }
    }
    for req in ["wal.log", "schema.rhype"] {
        if !present.contains(req) {
            missing.push(req.to_string());
        }
    }
    if !missing.is_empty() {
        anyhow::bail!(
            "backup is incomplete (truncated?) — missing: {}",
            missing.join(", ")
        );
    }
    let ssts = v
        .get("ssts")
        .and_then(|s| s.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    let max_version = v.get("max_version").and_then(|x| x.as_u64()).unwrap_or(0);
    let migrating = v
        .get("in_flight_migrations")
        .and_then(|m| m.as_array())
        .map(|a| a.len())
        .unwrap_or(0);
    Ok(format!(
        "ssts={ssts} max_version={max_version} in_flight_migrations={migrating}"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    /// A unique scratch dir under the system temp, removed by the returned guard on drop.
    struct TmpDir(PathBuf);
    impl TmpDir {
        fn new() -> Self {
            static N: AtomicU64 = AtomicU64::new(0);
            let nanos = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos();
            let p = std::env::temp_dir().join(format!(
                "jkbase-backup-test-{}-{}",
                std::process::id(),
                nanos ^ (N.fetch_add(1, Ordering::Relaxed) as u128)
            ));
            std::fs::create_dir_all(&p).unwrap();
            Self(p)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }
    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    #[test]
    fn rejects_bad_ids() {
        let s = BackupStore::new(Path::new("/tmp/x"));
        assert!(s.object_path("../etc", "bkp_1_a").is_err());
        assert!(s.object_path("proj", "../evil").is_err());
        assert!(s.object_path("proj", "bkp_1_ab").is_ok());
        assert!(!is_valid_project_id(""));
        assert!(!is_valid_backup_id("bkp/evil"));
        assert!(is_valid_backup_id("bkp_123_deadbeef"));
    }

    #[tokio::test]
    async fn stage_commit_read_delete_roundtrip() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let mut src = std::io::Cursor::new(b"hello-tar-bytes".to_vec());
        let staged = store
            .stage("proj-a", "bkp_1_aa", &mut src, 1024)
            .await
            .unwrap();
        assert_eq!(staged.size_bytes, 15);
        store.commit(staged).await.unwrap();
        let mut f = store.open_read("proj-a", "bkp_1_aa").await.unwrap();
        use tokio::io::AsyncReadExt;
        let mut got = Vec::new();
        f.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"hello-tar-bytes");
        store.delete("proj-a", "bkp_1_aa").await.unwrap();
        assert!(store.open_read("proj-a", "bkp_1_aa").await.is_err());
        // Idempotent delete.
        store.delete("proj-a", "bkp_1_aa").await.unwrap();
    }

    #[tokio::test]
    async fn stage_enforces_cap() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let mut src = std::io::Cursor::new(vec![0u8; 4096]);
        assert!(store.stage("p", "bkp_1_a", &mut src, 1024).await.is_err());
    }

    /// Build a rhypedb-shaped backup tar containing exactly `entries` (name → bytes) plus a
    /// MANIFEST.json listing `manifest_ssts` (unless `omit_manifest`).
    fn make_tar(entries: &[(&str, &[u8])], manifest_ssts: &[&str], omit_manifest: bool) -> Vec<u8> {
        let mut out = Vec::new();
        {
            let mut b = tar::Builder::new(&mut out);
            let append = |b: &mut tar::Builder<&mut Vec<u8>>, name: &str, data: &[u8]| {
                let mut h = tar::Header::new_gnu();
                h.set_size(data.len() as u64);
                h.set_cksum();
                b.append_data(&mut h, name, data).unwrap();
            };
            for (name, data) in entries {
                append(&mut b, name, data);
            }
            if !omit_manifest {
                let m = serde_json::json!({
                    "ssts": manifest_ssts, "max_version": 5, "in_flight_migrations": [],
                });
                let mb = serde_json::to_vec(&m).unwrap();
                append(&mut b, "MANIFEST.json", &mb);
            }
            b.finish().unwrap();
        }
        out
    }

    async fn stage_tar(store: &BackupStore, id: &str, bytes: Vec<u8>) -> StagedBackup {
        let mut src = std::io::Cursor::new(bytes);
        store.stage("p", id, &mut src, 1 << 20).await.unwrap()
    }

    #[tokio::test]
    async fn validate_accepts_a_complete_backup() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let tar = make_tar(
            &[
                ("sst/1.sst", b"a"),
                ("sst/2.sst", b"bb"),
                ("wal.log", b"w"),
                ("schema.rhype", b"type X {}"),
            ],
            &["1.sst", "2.sst"],
            false,
        );
        let staged = stage_tar(&store, "bkp_ok", tar).await;
        let summary = store.validate(&staged).await.unwrap();
        assert!(summary.contains("ssts=2"), "{summary}");
        store.discard(staged).await;
    }

    #[tokio::test]
    async fn validate_rejects_missing_manifest() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let tar = make_tar(&[("sst/1.sst", b"a"), ("wal.log", b"w")], &["1.sst"], true);
        let staged = stage_tar(&store, "bkp_nomani", tar).await;
        assert!(
            store.validate(&staged).await.is_err(),
            "no MANIFEST.json ⇒ incomplete"
        );
        store.discard(staged).await;
    }

    #[tokio::test]
    async fn validate_rejects_manifest_present_but_sst_missing() {
        // [RB8] the core truncation case: MANIFEST.json made it (it is NOT last in the stream)
        // but a manifest-listed SST did not. Must be rejected, not committed Complete.
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let tar = make_tar(
            &[("wal.log", b"w"), ("schema.rhype", b"type X {}")],
            &["1.sst", "2.sst"], // manifest promises 2 ssts, tar has none
            false,
        );
        let staged = stage_tar(&store, "bkp_trunc", tar).await;
        let err = store.validate(&staged).await.unwrap_err().to_string();
        assert!(
            err.contains("incomplete") && err.contains("sst/1.sst"),
            "{err}"
        );
        store.discard(staged).await;
    }

    #[tokio::test]
    async fn validate_rejects_missing_wal_or_schema() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let tar = make_tar(&[("sst/1.sst", b"a")], &["1.sst"], false); // no wal.log/schema.rhype
        let staged = stage_tar(&store, "bkp_nowal", tar).await;
        assert!(store.validate(&staged).await.is_err());
        store.discard(staged).await;
    }

    #[tokio::test]
    async fn validate_rejects_gnu_longname_entry_before_parsing() {
        // The tar PARSER would buffer a GNU long-name ('L') entry body into RAM before yielding
        // an entry — the host-OOM vector. Craft a tar whose first header is typeflag 'L' with a
        // large declared size; the header pre-scan must reject it without allocating the body.
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let mut hdr = [0u8; 512];
        hdr[156] = b'L'; // GNU long-name typeflag
        // size field @124..136 = octal for a big value (e.g. 100 MiB) — we only write a little.
        let octal = b"00650000000\0"; // 0o6500000000 = 100 MiB-ish, fits 11 octal digits
        hdr[124..124 + octal.len()].copy_from_slice(octal);
        let mut tar = hdr.to_vec();
        tar.extend_from_slice(&[b'x'; 512]); // one data block (far less than declared)
        let staged = stage_tar(&store, "bkp_evil", tar).await;
        let err = store.validate(&staged).await.unwrap_err().to_string();
        assert!(err.contains("unsupported entry type"), "{err}");
        store.discard(staged).await;
    }

    #[tokio::test]
    async fn validate_rejects_manifest_with_traversal_sst_name() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        let tar = make_tar(
            &[("wal.log", b"w"), ("schema.rhype", b"type X {}")],
            &["../evil.sst"],
            false,
        );
        let staged = stage_tar(&store, "bkp_trav", tar).await;
        let err = store.validate(&staged).await.unwrap_err().to_string();
        assert!(err.contains("unsafe sst filename"), "{err}");
        store.discard(staged).await;
    }
}
