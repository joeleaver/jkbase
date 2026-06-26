//! Per-project on-disk storage accounting, shared by the host metering sampler
//! (jkbase-server) and the deploy-time storage cap (jkbase-control) so both
//! measure the same bytes.
//!
//! Billed storage = user-controllable data: the content image, the data disk
//! (actual blocks, not the logical size), and the LIVE deployment version. The
//! snapshot/mem files (platform-managed hibernation artifacts) and retained
//! rollback history (older `deployments/v*`) are deliberately EXCLUDED — so
//! scale-to-zero isn't penalized and a project's usable quota is its live
//! footprint, not `cap − history`. Symlinks are never followed for sizing.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Total billed storage bytes for `project_id` under `data_dir`: the content
/// image, the data disk, and the **live** deployment version only. Retained
/// rollback history (older `deployments/v*`) is platform-managed — bounded by a
/// deployment count, not the storage cap — and is deliberately NOT billed, so a
/// project's usable quota is its live footprint, not `cap − retained history`.
pub fn project_storage_bytes(data_dir: &Path, project_id: &str) -> u64 {
    // Follow the `live` symlink to the active deployment dir. read_link (not
    // canonicalize) so a dangling link mid-deploy just yields 0 deployment bytes.
    let live = data_dir.join("hosting").join(project_id).join("live");
    let live_dir = match std::fs::read_link(&live) {
        Ok(t) if t.is_absolute() => t,
        Ok(t) => live.parent().map(|p| p.join(&t)).unwrap_or(t),
        Err(_) => live, // no live version yet -> dir_bytes() returns 0
    };
    project_storage_bytes_for(data_dir, project_id, &live_dir)
}

/// Like [`project_storage_bytes`] but bills a specific deployment directory. Used
/// at deploy time to check the NEW version against the cap before the `live`
/// symlink is repointed to it — so the cap reflects the would-be-live footprint
/// (content image + data disk + this one version), never the transient old+new
/// peak, and a deploy whose live footprint fits is never refused by old versions.
pub fn project_storage_bytes_for(data_dir: &Path, project_id: &str, deployment_dir: &Path) -> u64 {
    let mut total = 0u64;

    // Content image: a plain file; logical length is fine.
    let content = data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));
    if let Ok(md) = std::fs::metadata(&content) {
        total = total.saturating_add(md.len());
    }

    // Data disk: a sparse image (logical 1 GiB); bill ACTUAL blocks used. Loop-managed
    // as `{id}.img`; pre-substrate deployments used `{id}.ext4` — fall back to it so the
    // quota cap + metering keep counting the disk after the rename.
    let disks = data_dir.join("data-disks");
    let disk = {
        let img = disks.join(format!("{project_id}.img"));
        if img.exists() {
            img
        } else {
            disks.join(format!("{project_id}.ext4"))
        }
    };
    if let Ok(md) = std::fs::metadata(&disk) {
        total = total.saturating_add(md.blocks().saturating_mul(512));
    }

    // Build cache drives: per-`(project,language)` sparse warm-cache images under
    // `buildcache/{id}/`. Bill ACTUAL blocks (sparse, grows on demand) like the data
    // disk. (Transiently moved into the jail during a build, so it may not be counted
    // then; quota is checked at build intake and the image returns afterwards.)
    if let Ok(entries) = std::fs::read_dir(data_dir.join("buildcache").join(project_id)) {
        for e in entries.flatten() {
            if let Ok(md) = e.metadata()
                && md.is_file()
            {
                total = total.saturating_add(md.blocks().saturating_mul(512));
            }
        }
    }

    // Tenant object store: per-project root `objectstore/{id}` holding S3 buckets
    // (object bytes + .meta sidecars + in-flight multipart staging). Counted here so
    // it bills against the SAME storage cap and shows in the SAME metering rollup as
    // everything else — one edit covers both the deploy gate and the hourly sampler.
    total = total.saturating_add(dir_bytes(&data_dir.join("objectstore").join(project_id)));

    // The single deployment version being billed (live, or the one being
    // deployed). Excludes other retained versions; never follows symlinks.
    total = total.saturating_add(dir_bytes(deployment_dir));

    total
}

/// Recursively sum regular-file sizes under `dir`, never following symlinks
/// (so the `live` -> deployments link is not traversed). Missing dir -> 0.
pub fn dir_bytes(dir: &Path) -> u64 {
    let mut total = 0u64;
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return 0,
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let md = match std::fs::symlink_metadata(&path) {
            Ok(md) => md,
            Err(_) => continue,
        };
        let ft = md.file_type();
        if ft.is_symlink() {
            continue;
        } else if ft.is_dir() {
            total = total.saturating_add(dir_bytes(&path));
        } else if ft.is_file() {
            total = total.saturating_add(md.len());
        }
    }
    total
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    // Hermetic temp dir without external deps; unique per (pid, tag).
    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("jkb-storage-{}-{tag}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn write(path: &Path, bytes: &[u8]) {
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(path, bytes).unwrap();
    }

    #[test]
    fn bills_content_plus_live_version_only_not_history() {
        let dd = tmp("live-only");
        let pid = "proj";
        write(&dd.join("content-images").join("proj.ext4"), &[0u8; 100]);
        let dep = dd.join("hosting").join(pid).join("deployments");
        write(&dep.join("v1").join("index.html"), &[0u8; 1000]); // retained history
        write(&dep.join("v2").join("index.html"), &[0u8; 50]); // live
        std::os::unix::fs::symlink(dep.join("v2"), dd.join("hosting").join(pid).join("live"))
            .unwrap();

        // Live: content(100) + v2(50) = 150; the retained v1(1000) is NOT billed.
        assert_eq!(project_storage_bytes(&dd, pid), 150);
        // Deploy-time check bills a specific version dir (content + that dir).
        assert_eq!(project_storage_bytes_for(&dd, pid, &dep.join("v1")), 1100);
        assert_eq!(project_storage_bytes_for(&dd, pid, &dep.join("v2")), 150);
        let _ = fs::remove_dir_all(&dd);
    }

    #[test]
    fn bills_object_store_bytes() {
        let dd = tmp("objstore");
        let pid = "proj";
        write(&dd.join("content-images").join("proj.ext4"), &[0u8; 100]);
        // Object store: a bucket dir with an object + its .meta sidecar.
        let bkt = dd.join("objectstore").join(pid).join("my-bucket");
        write(&bkt.join("deadbeef"), &[0u8; 500]);
        write(&bkt.join("deadbeef.meta"), &[0u8; 30]);
        // content(100) + object(500) + meta(30) = 630; no deployment yet.
        assert_eq!(project_storage_bytes(&dd, pid), 630);
        let _ = fs::remove_dir_all(&dd);
    }

    #[test]
    fn no_live_symlink_bills_content_only() {
        let dd = tmp("no-live");
        let pid = "p";
        write(&dd.join("content-images").join("p.ext4"), &[0u8; 42]);
        // History on disk but no `live` symlink yet -> not billed.
        write(
            &dd.join("hosting")
                .join(pid)
                .join("deployments")
                .join("v1")
                .join("f"),
            &[0u8; 999],
        );
        assert_eq!(project_storage_bytes(&dd, pid), 42);
        let _ = fs::remove_dir_all(&dd);
    }
}
