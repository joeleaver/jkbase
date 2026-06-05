//! Per-project on-disk storage accounting, shared by the host metering sampler
//! (jkbase-server) and the deploy-time storage cap (jkbase-control) so both
//! measure the same bytes.
//!
//! Billed storage = user-controllable data: the content image, the data disk
//! (actual blocks, not the logical size), and deployment artifacts. The
//! snapshot/mem files (platform-managed hibernation artifacts) are deliberately
//! EXCLUDED so scale-to-zero isn't penalized. Symlinks (e.g. the `live` ->
//! deployment link) are never followed, to avoid double-counting.

use std::os::unix::fs::MetadataExt;
use std::path::Path;

/// Total billed storage bytes for `project_id` under `data_dir`.
pub fn project_storage_bytes(data_dir: &Path, project_id: &str) -> u64 {
    let mut total = 0u64;

    // Content image: a plain file; logical length is fine.
    let content = data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));
    if let Ok(md) = std::fs::metadata(&content) {
        total = total.saturating_add(md.len());
    }

    // Data disk: a sparse ext4 image (logical 1 GiB); bill ACTUAL blocks used.
    let disk = data_dir
        .join("data-disks")
        .join(format!("{project_id}.ext4"));
    if let Ok(md) = std::fs::metadata(&disk) {
        total = total.saturating_add(md.blocks().saturating_mul(512));
    }

    // Deployment artifacts (all versions). Excludes the `live` symlink.
    let deployments = data_dir.join("hosting").join(project_id).join("deployments");
    total = total.saturating_add(dir_bytes(&deployments));

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
