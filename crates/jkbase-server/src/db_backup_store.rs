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
        Ok(self.project_dir(project_id)?.join(format!("{backup_id}.tar")))
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
        let mut f = tokio::fs::File::create(&tmp)
            .await
            .context("create backup tmp")?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut size: u64 = 0;
        loop {
            let n = reader.read(&mut buf).await.context("read backup stream")?;
            if n == 0 {
                break;
            }
            size += n as u64;
            if size > max_bytes {
                let _ = tokio::fs::remove_file(&tmp).await;
                anyhow::bail!("backup exceeds {max_bytes} bytes");
            }
            f.write_all(&buf[..n]).await.context("write backup tmp")?;
        }
        f.flush().await.context("flush backup tmp")?;
        Ok(StagedBackup {
            tmp,
            final_path,
            size_bytes: size,
        })
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

/// Validate a completed backup tar and extract a one-line summary from its `MANIFEST.json`
/// ([RB8]). rhypedb writes `MANIFEST.json` LAST, so its presence proves the stream wasn't
/// truncated. Sync (tar is a blocking reader) — run under `spawn_blocking`. Errs if the tar is
/// unreadable or has no `MANIFEST.json` (⇒ the backup is truncated/corrupt → not restorable).
pub fn validate_and_summarize(tar_path: &Path) -> Result<String> {
    let f = std::fs::File::open(tar_path).context("open backup for validation")?;
    let mut ar = tar::Archive::new(f);
    let mut manifest_bytes: Option<Vec<u8>> = None;
    for entry in ar.entries().context("read backup entries")? {
        let mut entry = entry.context("read backup entry (truncated?)")?;
        let path = entry.path().context("backup entry path")?;
        if path.file_name().and_then(|n| n.to_str()) == Some("MANIFEST.json") {
            use std::io::Read;
            let mut b = Vec::new();
            entry.read_to_end(&mut b).context("read MANIFEST.json")?;
            manifest_bytes = Some(b);
            break;
        }
    }
    let bytes = manifest_bytes
        .ok_or_else(|| anyhow::anyhow!("backup is incomplete: no MANIFEST.json (truncated stream)"))?;
    let v: serde_json::Value =
        serde_json::from_slice(&bytes).context("parse backup MANIFEST.json")?;
    let ssts = v.get("ssts").and_then(|s| s.as_array()).map(|a| a.len()).unwrap_or(0);
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
        let staged = store.stage("proj-a", "bkp_1_aa", &mut src, 1024).await.unwrap();
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

    #[tokio::test]
    async fn validate_rejects_non_tar_and_missing_manifest() {
        let dir = TmpDir::new();
        let store = BackupStore::new(dir.path());
        // A tar with files but NO MANIFEST.json ⇒ treated as truncated/incomplete ([RB8]).
        let mut tar_bytes = Vec::new();
        {
            let mut b = tar::Builder::new(&mut tar_bytes);
            let data = b"sst-bytes";
            let mut h = tar::Header::new_gnu();
            h.set_size(data.len() as u64);
            h.set_cksum();
            b.append_data(&mut h, "sst/1.sst", &data[..]).unwrap();
            b.finish().unwrap();
        }
        let mut src = std::io::Cursor::new(tar_bytes);
        let staged = store.stage("p", "bkp_1_a", &mut src, 1 << 20).await.unwrap();
        assert!(store.validate(&staged).await.is_err(), "no MANIFEST.json ⇒ incomplete");
        store.discard(staged).await;
    }
}
