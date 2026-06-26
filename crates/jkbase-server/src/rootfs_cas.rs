//! Content-addressed storage for the guest base rootfs, so a redeploy that ships a new
//! agent can NEVER poison a pre-existing hibernation snapshot.
//!
//! The old failure (incident: project `nlnwt`, 2026-06-26): `base-rootfs.ext4` was rebuilt
//! IN PLACE every deploy, and snapshots reference the rootfs by fixed path. A VM hibernated
//! under the old bytes then restored its old guest RAM against the new bytes (Firecracker
//! lazily mmap-faults rootfs pages for the VM's whole life) → the in-VM agent faulted a
//! changed page and never came ready → the proxy wake-looped forever.
//!
//! Fix: hash the rootfs and store it immutably at `base-rootfs/<sha256>.ext4`. A new agent
//! mints a NEW hash/blob ALONGSIDE the old one; the old blob is retained as long as any
//! snapshot still references it, so the restore stays byte-correct. The startup GC reaps
//! only blobs no restorable snapshot needs, and it FAILS CLOSED (deletes nothing if it
//! can't prove a blob is unreferenced). See `docs/rootfs-cas-snapshot-durability.md`.

use anyhow::{Context, Result};
use std::collections::HashSet;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// A validated 64-hex sha256 digest — the only shape we ever join into a CAS path or accept
/// as a blob name, so a corrupt redb value / future refactor can't turn the hash into path
/// traversal or a stray delete.
pub fn is_sha256_hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit())
}

fn sha256_file(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).with_context(|| format!("hash {}", path.display()))?;
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
}

/// The immutable blob path for a digest. Caller MUST pass an `is_sha256_hex` digest.
pub fn blob_path(cas_dir: &Path, hash: &str) -> PathBuf {
    cas_dir.join(format!("{hash}.ext4"))
}

/// Hash `staging` and place it immutably at `cas_dir/<sha256>.ext4`, returning the blob path
/// and digest. Atomic: a partial copy lands at a `.tmp` name and is renamed into place only
/// after `fsync`, so a crash never leaves a truncated blob under a valid-looking hash that a
/// later "skip if exists" would trust (which would silently corrupt every future boot). The
/// blob is `0444` to make any in-place rewrite fail loudly. A `current` symlink is refreshed
/// for ops visibility (the process pins the real path; GC ignores the symlink).
///
/// Run ONCE at startup, synchronously, before any VM can boot — the few-hundred-ms hash of a
/// ~117 MiB ext4 happens while all projects are down, and the result is the boot rootfs for
/// every VM this incarnation starts.
pub fn place(staging: &Path, cas_dir: &Path) -> Result<(PathBuf, String)> {
    std::fs::create_dir_all(cas_dir)
        .with_context(|| format!("create cas dir {}", cas_dir.display()))?;
    let hash = sha256_file(staging)?;
    let dest = blob_path(cas_dir, &hash);

    // skip-if-exists is only ever trusted for a blob we wrote via the atomic rename below
    // (and left 0444). A pre-existing regular file at the content-addressed name is, by
    // construction, the same bytes.
    if !dest.is_file() {
        let tmp = cas_dir.join(format!(".{hash}.{}.tmp", std::process::id()));
        let _ = std::fs::remove_file(&tmp);
        std::fs::copy(staging, &tmp)
            .with_context(|| format!("copy {} -> {}", staging.display(), tmp.display()))?;
        // fsync the bytes before exposing them under the final name.
        {
            let f = std::fs::File::open(&tmp)?;
            f.sync_all().context("fsync cas blob")?;
        }
        let mut perms = std::fs::metadata(&tmp)?.permissions();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            perms.set_mode(0o444);
        }
        let _ = std::fs::set_permissions(&tmp, perms);
        std::fs::rename(&tmp, &dest)
            .with_context(|| format!("rename {} -> {}", tmp.display(), dest.display()))?;
        info!(hash = %hash, path = %dest.display(), "base rootfs content-addressed");
    } else {
        info!(hash = %hash, "base rootfs already content-addressed (dedup hit)");
    }

    refresh_current_symlink(cas_dir, &hash);
    Ok((dest, hash))
}

/// Best-effort atomic refresh of `cas_dir/current` -> `<hash>.ext4`. Purely for ops
/// visibility; the running process pins the real path via `base_rootfs_path`.
fn refresh_current_symlink(cas_dir: &Path, hash: &str) {
    #[cfg(unix)]
    {
        let link = cas_dir.join("current");
        let tmp = cas_dir.join(".current.tmp");
        let _ = std::fs::remove_file(&tmp);
        if std::os::unix::fs::symlink(format!("{hash}.ext4"), &tmp).is_ok() {
            let _ = std::fs::rename(&tmp, &link);
        }
    }
}

/// Delete CAS blobs no restorable snapshot needs. `keep` is the referenced set
/// (`{current_hash} ∪ {every snapshot's stamped base_rootfs_hash}`). Returns the hashes
/// removed.
///
/// FAIL CLOSED: the caller must skip this entirely if it could not fully enumerate the
/// referenced set (a partial set would reap a live blob). Here we only ever touch entries
/// that are regular files named `<64hex>.ext4` (never the `current` symlink) plus our own
/// leftover `.tmp` scratch; `current_hash` is always in `keep`, so a blob a running VM maps
/// is safe regardless. Over-deletion is itself self-healing (a missing blob makes a restore
/// non-viable → cold boot), so this is defense in depth, not the only guard.
pub fn gc(cas_dir: &Path, keep: &HashSet<String>) -> Result<Vec<String>> {
    let mut removed = Vec::new();
    let rd = match std::fs::read_dir(cas_dir) {
        Ok(rd) => rd,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(removed),
        Err(e) => return Err(e).context("read cas dir"),
    };
    for entry in rd {
        let entry = entry?;
        let ft = entry.file_type()?;
        if !ft.is_file() {
            continue; // skip the `current` symlink, any subdir
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        // Reap our own leftover scratch from an interrupted place().
        if name.starts_with('.') && name.ends_with(".tmp") {
            let _ = std::fs::remove_file(entry.path());
            continue;
        }
        let Some(hash) = name.strip_suffix(".ext4") else {
            continue;
        };
        if !is_sha256_hex(hash) {
            continue; // never parse a non-digest name as a hash
        }
        if keep.contains(hash) {
            continue;
        }
        match std::fs::remove_file(entry.path()) {
            Ok(()) => {
                info!(hash = %hash, "GC: reaped unreferenced base-rootfs blob");
                removed.push(hash.to_string());
            }
            Err(e) => warn!(hash = %hash, error = %e, "GC: failed to reap base-rootfs blob"),
        }
    }
    Ok(removed)
}

/// SIGKILL any `firecracker` process whose `--api-sock` lives under `runtime_dir` — orphans
/// from a PRIOR incarnation that exited non-gracefully (OOM / SIGKILL / panic-abort), where
/// tokio's `kill_on_drop` never fired so the jailer/FC reparented to init and kept faulting
/// its rootfs blob. Run at startup BEFORE CAS placement + GC so the "zero VMs running"
/// premise the GC reference set depends on actually holds. Returns the count killed.
///
/// Targeted by the `--api-sock <runtime_dir>/...` argument — NEVER a `pkill -f firecracker`
/// substring match (which could reap an unrelated process / a project whose id is a substring
/// of another). At startup none of OUR VMs exist yet, so every match is genuinely an orphan.
pub fn reap_orphan_firecrackers(runtime_dir: &Path) -> usize {
    let run_prefix = runtime_dir.to_string_lossy().to_string();
    let mut victims: Vec<i32> = Vec::new();
    let Ok(rd) = std::fs::read_dir("/proc") else {
        return 0;
    };
    for entry in rd.flatten() {
        let name = entry.file_name();
        let Some(pid) = name.to_str().and_then(|s| s.parse::<i32>().ok()) else {
            continue;
        };
        let Ok(raw) = std::fs::read(format!("/proc/{pid}/cmdline")) else {
            continue;
        };
        // cmdline is NUL-separated argv.
        let args: Vec<&str> = raw
            .split(|b| *b == 0)
            .filter_map(|s| std::str::from_utf8(s).ok())
            .filter(|s| !s.is_empty())
            .collect();
        if args.is_empty() {
            continue;
        }
        let is_fc = args[0]
            .rsplit('/')
            .next()
            .unwrap_or("")
            .contains("firecracker");
        let under_run = args.iter().any(|a| a.contains(&run_prefix));
        if is_fc && under_run {
            victims.push(pid);
        }
    }
    for pid in &victims {
        warn!(pid = %pid, "reaping orphaned Firecracker from a prior incarnation");
        // SIGKILL by exact PID; dependency-free.
        let _ = std::process::Command::new("kill")
            .arg("-KILL")
            .arg(pid.to_string())
            .status();
    }
    victims.len()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_digest_shape() {
        assert!(is_sha256_hex(&"a".repeat(64)));
        assert!(is_sha256_hex(&"0123456789abcdef".repeat(4)));
        assert!(!is_sha256_hex(&"a".repeat(63)));
        assert!(!is_sha256_hex(&"a".repeat(65)));
        assert!(!is_sha256_hex(&"g".repeat(64))); // non-hex
        assert!(!is_sha256_hex("../../etc/passwd"));
    }

    #[test]
    fn place_is_idempotent_and_immutable() {
        let dir = std::env::temp_dir().join(format!("rootfs-cas-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let staging = dir.join("base-rootfs.ext4");
        std::fs::write(&staging, b"fake rootfs bytes").unwrap();
        let cas = dir.join("base-rootfs");

        let (p1, h1) = place(&staging, &cas).unwrap();
        let (p2, h2) = place(&staging, &cas).unwrap();
        assert_eq!(h1, h2);
        assert_eq!(p1, p2);
        assert!(p1.is_file());
        assert!(p1.file_name().unwrap().to_string_lossy().starts_with(&h1));
        // 0444 — immutable.
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&p1).unwrap().permissions().mode();
            assert_eq!(mode & 0o222, 0, "blob must be read-only");
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn gc_keeps_referenced_reaps_rest_and_skips_garbage() {
        let dir = std::env::temp_dir().join(format!("rootfs-gc-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let keep_hash = "a".repeat(64);
        let drop_hash = "b".repeat(64);
        std::fs::write(blob_path(&dir, &keep_hash), b"keep").unwrap();
        std::fs::write(blob_path(&dir, &drop_hash), b"drop").unwrap();
        // A non-digest file must be left untouched.
        std::fs::write(dir.join("README.txt"), b"not a blob").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(format!("{keep_hash}.ext4"), dir.join("current")).unwrap();

        let keep: HashSet<String> = [keep_hash.clone()].into_iter().collect();
        let mut removed = gc(&dir, &keep).unwrap();
        removed.sort();
        assert_eq!(removed, vec![drop_hash.clone()]);
        assert!(blob_path(&dir, &keep_hash).is_file());
        assert!(!blob_path(&dir, &drop_hash).exists());
        assert!(dir.join("README.txt").is_file());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
