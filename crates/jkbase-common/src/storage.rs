//! Per-project on-disk storage accounting, shared by the host metering sampler
//! (jkbase-server) and the storage caps (deploy-time in jkbase-control, object-store writes
//! and data-disk sizing in jkbase-server) so all of them measure the same files.
//!
//! Counted storage = user-controllable data: the content images, the data disks, the build
//! caches, the object store, and the LIVE deployment version. The snapshot/mem files
//! (platform-managed hibernation artifacts) and retained rollback history (older
//! `deployments/v*`) are deliberately EXCLUDED — so scale-to-zero isn't penalized and a
//! project's usable quota is its live footprint, not `cap − history`. Symlinks are never
//! followed for sizing.
//!
//! Two views differ ONLY in how a data disk counts:
//! - **Billed** ([`project_storage_bytes`]): a disk's ACTUAL allocated blocks — what the host
//!   really spends, metered for usage/billing.
//! - **Reserved** ([`project_reserved_bytes`]): a disk at its full LOGICAL size — what its guest
//!   can fill between checks with no host in the loop. Every quota CHECK uses this view, so the
//!   quota bounds host capacity even if a tenant fills its disks after the check, and filling a
//!   disk can never newly push a project over its cap (freed guest blocks aren't returned to a
//!   sparse image — the guest disk has no discard — so an allocated-blocks cap would only ratchet).

use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

/// How a data disk counts toward a footprint (see the module docs).
#[derive(Clone, Copy)]
enum DiskView {
    Billed,
    Reserved,
}

/// Follow the `live` symlink to the active deployment dir. read_link (not canonicalize) so a
/// dangling link mid-deploy just yields 0 deployment bytes; no live version yet → the (absent)
/// link path itself, which `dir_bytes` counts as 0.
fn live_dir(data_dir: &Path, project_id: &str) -> PathBuf {
    let live = data_dir.join("hosting").join(project_id).join("live");
    match std::fs::read_link(&live) {
        Ok(t) if t.is_absolute() => t,
        Ok(t) => live.parent().map(|p| p.join(&t)).unwrap_or(t),
        Err(_) => live,
    }
}

/// Total billed storage bytes for `project_id` under `data_dir`: the content images, the data
/// disks (app + dedicated DB, by allocated blocks), and the **live** deployment version only.
/// Retained rollback history (older `deployments/v*`) is platform-managed — bounded by a
/// deployment count, not the storage cap — and is deliberately NOT billed, so a project's usable
/// quota is its live footprint, not `cap − retained history`.
pub fn project_storage_bytes(data_dir: &Path, project_id: &str) -> u64 {
    project_storage_bytes_for(data_dir, project_id, &live_dir(data_dir, project_id))
}

/// Like [`project_storage_bytes`] but bills a specific deployment directory.
pub fn project_storage_bytes_for(data_dir: &Path, project_id: &str, deployment_dir: &Path) -> u64 {
    footprint(data_dir, project_id, deployment_dir, DiskView::Billed)
}

/// The quota-enforcement footprint of the live project: [`project_storage_bytes`] with each data
/// disk counted at its full logical size (the module docs say why).
pub fn project_reserved_bytes(data_dir: &Path, project_id: &str) -> u64 {
    project_reserved_bytes_for(data_dir, project_id, &live_dir(data_dir, project_id))
}

/// Like [`project_reserved_bytes`] but for a specific deployment directory. Used at deploy time
/// to check the NEW version against the cap before the `live` symlink is repointed to it — so the
/// cap reflects the would-be-live footprint (this one version), never the transient old+new peak,
/// and a deploy whose live footprint fits is never refused by old versions.
pub fn project_reserved_bytes_for(data_dir: &Path, project_id: &str, deployment_dir: &Path) -> u64 {
    footprint(data_dir, project_id, deployment_dir, DiskView::Reserved)
}

/// The deploy-time storage cap: `Some(footprint)` when deploying `deployment_dir` must be REFUSED.
/// The footprint is the would-be-live [`project_reserved_bytes_for`]. Refused only when it exceeds
/// `cap` AND grows the project past what is live now: a project already over its cap (quota
/// lowered, or disks sized before the cap counted them all) may still ship a deploy that doesn't
/// grow it — refusing would lock it out of shipping fixes while bounding nothing.
pub fn deploy_exceeds_cap(
    data_dir: &Path,
    project_id: &str,
    deployment_dir: &Path,
    cap: u64,
) -> Option<u64> {
    let footprint = project_reserved_bytes_for(data_dir, project_id, deployment_dir);
    (footprint > cap && footprint > project_reserved_bytes(data_dir, project_id))
        .then_some(footprint)
}

/// The project's data disks at their full logical size — the share of
/// [`project_reserved_bytes`] that its guests can fill without a host-side check.
pub fn data_disks_reserved_bytes(data_dir: &Path, project_id: &str) -> u64 {
    data_disk_images(data_dir, project_id)
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok())
        .fold(0, |acc, md| acc.saturating_add(disk_bytes(&md, DiskView::Reserved)))
}

fn disk_bytes(md: &std::fs::Metadata, view: DiskView) -> u64 {
    let allocated = md.blocks().saturating_mul(512);
    match view {
        DiskView::Billed => allocated,
        // `max`: a disk is never reserved below what it already holds.
        DiskView::Reserved => allocated.max(md.len()),
    }
}

fn footprint(data_dir: &Path, project_id: &str, deployment_dir: &Path, view: DiskView) -> u64 {
    let mut total = 0u64;

    // Content images: plain files; logical length is fine. A dedicated DB VM's own metadata
    // image (`{id}.db.ext4`) is the project's too — billed here, not on the `{id}.db` usage row.
    for name in [format!("{project_id}.ext4"), format!("{project_id}.db.ext4")] {
        if let Ok(md) = std::fs::metadata(data_dir.join("content-images").join(name)) {
            total = total.saturating_add(md.len());
        }
    }

    // Data disks: sparse images, counted per `view` (allocated blocks vs logical size). Every
    // disk the project owns counts against the ONE cap — a dedicated DB's sibling `{id}.db.img`
    // included, or a dedicated project could fill its quota on each disk.
    for disk in data_disk_images(data_dir, project_id) {
        if let Ok(md) = std::fs::metadata(&disk) {
            total = total.saturating_add(disk_bytes(&md, view));
        }
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

    // Build-reuse cache (`buildcache/{id}/targets/…`): a cached artifact is usually a hard
    // link to the same file in the billed deployment. Bill each distinct inode ONCE, skipping
    // the ones that deployment already paid for — link count alone would let two cache entries
    // sharing an inode (or one shared with a retained, unbilled version) bill nothing.
    let mut seen = std::collections::HashSet::new();
    collect_inodes(deployment_dir, &mut seen);
    total = total.saturating_add(unshared_file_bytes(
        &data_dir.join("buildcache").join(project_id).join("targets"),
        &mut seen,
    ));

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

/// The project's data-disk images under `data-disks/` (existing files only): the app VM's
/// loop-managed `{id}.img` — or the pre-substrate `{id}.ext4` it was renamed from, so billing
/// keeps counting the disk across the rename — and a dedicated managed DB's sibling
/// `{id}.db.img` (the DB VM's rendered id, `vm_identity::vm_id(id, Db)` in jkbase-server).
/// Shared by billing and the host's project-wide disk-size cap so both see the same disks.
pub fn data_disk_images(data_dir: &Path, project_id: &str) -> Vec<PathBuf> {
    let disks = data_dir.join("data-disks");
    let img = disks.join(format!("{project_id}.img"));
    let app = if img.exists() {
        img
    } else {
        disks.join(format!("{project_id}.ext4"))
    };
    [app, disks.join(format!("{project_id}.db.img"))]
        .into_iter()
        .filter(|p| p.is_file())
        .collect()
}

/// Record every `(dev, ino)` of the regular files under `dir` (never following symlinks), so
/// a file hard-linked elsewhere is billed once, where it is already counted.
fn collect_inodes(dir: &Path, seen: &mut std::collections::HashSet<(u64, u64)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let Ok(md) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if md.is_dir() {
            collect_inodes(&entry.path(), seen);
        } else if md.is_file() {
            seen.insert((md.dev(), md.ino()));
        }
    }
}

/// Recursively sum the allocated blocks of regular files under `dir`, counting each distinct
/// inode once and skipping the ones in `seen` (already billed elsewhere). Never follows
/// symlinks. Missing dir -> 0.
pub fn unshared_file_bytes(dir: &Path, seen: &mut std::collections::HashSet<(u64, u64)>) -> u64 {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return 0;
    };
    let mut total = 0u64;
    for entry in entries.flatten() {
        let Ok(md) = std::fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if md.is_dir() {
            total = total.saturating_add(unshared_file_bytes(&entry.path(), seen));
        } else if md.is_file() && seen.insert((md.dev(), md.ino())) {
            total = total.saturating_add(md.blocks().saturating_mul(512));
        }
    }
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
    fn bills_build_cache_files_no_deployment_still_shares() {
        let dd = tmp("buildcache");
        let pid = "proj";
        let dep = dd.join("hosting").join(pid).join("deployments").join("v1");
        write(&dep.join("_layers").join("blob"), &[7u8; 8192]);
        std::os::unix::fs::symlink(&dep, dd.join("hosting").join(pid).join("live")).unwrap();
        let entries = dd.join("buildcache").join(pid).join("targets").join("server-api");
        // Shared with the live deployment (a hard link): billed once, via the deployment.
        fs::create_dir_all(entries.join("k1")).unwrap();
        fs::hard_link(dep.join("_layers").join("blob"), entries.join("k1").join("app.erofs")).unwrap();
        let with_shared = project_storage_bytes(&dd, pid);
        assert_eq!(with_shared, 8192, "a shared cache file is not billed twice");
        // An entry whose deployment is gone: its own blocks are billed…
        write(&entries.join("k0").join("app.erofs"), &[1u8; 8192]);
        assert_eq!(project_storage_bytes(&dd, pid), with_shared + 8192);
        // …and a second entry sharing THAT inode adds nothing, but doesn't hide it either
        // (link count > 1 with no billed deployment behind it).
        let other = dd.join("buildcache").join(pid).join("targets").join("server-web");
        fs::create_dir_all(&other).unwrap();
        fs::hard_link(entries.join("k0").join("app.erofs"), other.join("app.erofs")).unwrap();
        assert_eq!(project_storage_bytes(&dd, pid), with_shared + 8192);
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
    fn bills_dedicated_db_disk_allocated_blocks() {
        let dd = tmp("db-disk");
        let pid = "proj";
        let disks = dd.join("data-disks");
        fs::create_dir_all(&disks).unwrap();
        // Sparse: logical 64 MiB, nothing allocated → bills ~0, not the logical size.
        let sparse = |name: &str| {
            fs::File::create(disks.join(name)).unwrap().set_len(64 << 20).unwrap();
        };
        sparse("proj.img");
        sparse("proj.db.img");
        // Incompressible fill, so a compressing fs (btrfs/zfs) still allocates the blocks.
        let mut x = 0x9e37_79b9_u32;
        let noise: Vec<u8> = (0..1 << 20)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 17;
                x ^= x << 5;
                x as u8
            })
            .collect();
        let base = project_storage_bytes(&dd, pid);
        assert!(base < (1 << 20), "sparse disks bill allocated blocks, got {base}");
        // Real blocks written to the DB disk count against the SAME cap as the app disk.
        write(&disks.join("proj.db.img"), &noise);
        assert!(project_storage_bytes(&dd, pid) >= base + (1 << 20));
        write(&disks.join("proj.img"), &noise);
        assert!(project_storage_bytes(&dd, pid) >= base + (2 << 20));
        // The DB VM's metadata image is the project's too.
        let before = project_storage_bytes(&dd, pid);
        write(&dd.join("content-images").join("proj.db.ext4"), &[0u8; 77]);
        assert_eq!(project_storage_bytes(&dd, pid), before + 77);
        // Another project's DB disk is never billed here (exact-name match, not a prefix).
        let before = project_storage_bytes(&dd, pid);
        write(&disks.join("proj2.db.img"), &[1u8; 1 << 20]);
        write(&disks.join("proj.db.img.bak"), &[1u8; 1 << 20]);
        assert_eq!(project_storage_bytes(&dd, pid), before);
        assert_eq!(
            data_disk_images(&dd, pid),
            vec![disks.join("proj.img"), disks.join("proj.db.img")]
        );
        let _ = fs::remove_dir_all(&dd);
    }

    #[test]
    fn reserved_view_counts_disks_at_logical_size() {
        let dd = tmp("reserved");
        let pid = "proj";
        let disks = dd.join("data-disks");
        fs::create_dir_all(&disks).unwrap();
        write(&dd.join("content-images").join("proj.ext4"), &[0u8; 100]);
        let sparse = |name: &str, len: u64| {
            fs::File::create(disks.join(name)).unwrap().set_len(len).unwrap();
        };
        sparse("proj.img", 64 << 20);
        sparse("proj.db.img", 256 << 20);
        // Reserved: the content image + both disks at full size, though nothing is allocated.
        assert_eq!(project_reserved_bytes(&dd, pid), 100 + (64 << 20) + (256 << 20));
        assert_eq!(data_disks_reserved_bytes(&dd, pid), (64 << 20) + (256 << 20));
        // Billed: allocated blocks only — a small fraction of the reservation.
        assert!(project_storage_bytes(&dd, pid) < 100 + (1 << 20));
        // Filling a disk inside its size does not move the reservation (no ratchet to lock on).
        let f = fs::OpenOptions::new().write(true).open(disks.join("proj.db.img")).unwrap();
        std::os::unix::fs::FileExt::write_all_at(&f, &[7u8; 4096], 1 << 20).unwrap();
        f.sync_all().unwrap();
        assert_eq!(project_reserved_bytes(&dd, pid), 100 + (64 << 20) + (256 << 20));
        // A deployment dir counts in both views.
        let dep = dd.join("hosting").join(pid).join("deployments").join("v1");
        write(&dep.join("index.html"), &[0u8; 50]);
        assert_eq!(
            project_reserved_bytes_for(&dd, pid, &dep),
            150 + (64 << 20) + (256 << 20)
        );
        let _ = fs::remove_dir_all(&dd);
    }

    #[test]
    fn deploy_cap_counts_reserved_disks_but_never_locks_out_a_non_growing_deploy() {
        let dd = tmp("deploy-cap");
        let pid = "proj";
        let disks = dd.join("data-disks");
        fs::create_dir_all(&disks).unwrap();
        // A 1000-byte DB disk (logical; nothing written) + a live 100-byte version.
        fs::File::create(disks.join("proj.db.img")).unwrap().set_len(1000).unwrap();
        let deps = dd.join("hosting").join(pid).join("deployments");
        write(&deps.join("v1").join("f"), &[0u8; 100]);
        std::os::unix::fs::symlink(deps.join("v1"), dd.join("hosting").join(pid).join("live"))
            .unwrap();
        write(&deps.join("v2").join("f"), &[0u8; 200]);
        // The disk counts at full size: 1000 + 200 > 1100 though barely any block is allocated.
        assert_eq!(deploy_exceeds_cap(&dd, pid, &deps.join("v2"), 1100), Some(1200));
        assert_eq!(deploy_exceeds_cap(&dd, pid, &deps.join("v2"), 1200), None);
        // Already over the cap (1100 live > 500): a same-size or smaller deploy still ships…
        write(&deps.join("v3").join("f"), &[0u8; 100]);
        assert_eq!(deploy_exceeds_cap(&dd, pid, &deps.join("v3"), 500), None);
        // …a growing one does not.
        assert_eq!(deploy_exceeds_cap(&dd, pid, &deps.join("v2"), 500), Some(1200));
        let _ = fs::remove_dir_all(&dd);
    }

    #[test]
    fn data_disk_images_falls_back_to_legacy_ext4() {
        let dd = tmp("legacy-disk");
        let disks = dd.join("data-disks");
        assert!(data_disk_images(&dd, "p").is_empty());
        write(&disks.join("p.ext4"), &[0u8; 8]);
        assert_eq!(data_disk_images(&dd, "p"), vec![disks.join("p.ext4")]);
        // A directory squatting the DB-disk name is not a disk.
        fs::create_dir_all(disks.join("p.db.img")).unwrap();
        assert_eq!(data_disk_images(&dd, "p"), vec![disks.join("p.ext4")]);
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
