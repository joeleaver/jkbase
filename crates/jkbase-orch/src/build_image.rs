//! Build-VM drive images, populated from a directory **without mounting**.
//!
//! Unlike [`crate::rootfs`] (which `sudo` loopback-mounts an image to populate
//! it), these images are written with `mke2fs -d`, which lays down the
//! filesystem from a source directory entirely in userspace — no root, no loop
//! device, and crucially the host kernel never mounts/parses anything
//! (threat-model P0-3). Output is a read-only-friendly ext4 (no journal, so a RO
//! mount needs no recovery) and world-readable, so the image can be hard-linked
//! into a jail and opened by the dropped non-root build uid.

use anyhow::{bail, Context, Result};
use std::path::Path;

/// Build a read-only ext4 image at `out_path`, populated from `src_dir` and
/// sized to the directory's contents plus `headroom_mib`. No mount, no root.
///
/// Used for the build VM's source-snapshot drive and (platform-built) toolchain
/// images. Returns an error if `e2fsprogs` (`mkfs.ext4`) is unavailable.
pub fn build_ro_ext4_from_dir(src_dir: &Path, out_path: &Path, headroom_mib: u64) -> Result<()> {
    if !src_dir.is_dir() {
        bail!("source directory {} does not exist", src_dir.display());
    }

    // Size = content + 50% ext4 metadata slack + headroom, floored at 1 MiB.
    let content_kib = dir_size_kib(src_dir)?;
    let size_kib = (content_kib + content_kib / 2 + headroom_mib * 1024).max(1024);

    let status = std::process::Command::new("truncate")
        .arg("-s")
        .arg(format!("{size_kib}K"))
        .arg(out_path)
        .status()
        .with_context(|| format!("run truncate for {}", out_path.display()))?;
    if !status.success() {
        bail!("truncate failed for {} ({status})", out_path.display());
    }

    // Populate ext4 from the directory in userspace: no mount, no loop device,
    // no journal (a RO mount of a journalled fs needs recovery and fails).
    let status = std::process::Command::new("mkfs.ext4")
        .args(["-F", "-q", "-O", "^has_journal", "-d"])
        .arg(src_dir)
        .arg(out_path)
        .status()
        .with_context(|| {
            format!(
                "run mkfs.ext4 -d for {} (is e2fsprogs installed?)",
                out_path.display()
            )
        })?;
    if !status.success() {
        bail!("mkfs.ext4 failed for {} ({status})", out_path.display());
    }

    // World-readable: hard-linked into the jail, opened by the dropped build uid.
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(out_path)?.permissions();
    perms.set_mode(0o444);
    std::fs::set_permissions(out_path, perms)
        .with_context(|| format!("set 0444 on {}", out_path.display()))?;
    Ok(())
}

/// Apparent size of a directory tree in KiB, via `du -sk`.
fn dir_size_kib(dir: &Path) -> Result<u64> {
    let out = std::process::Command::new("du")
        .arg("-sk")
        .arg(dir)
        .output()
        .context("run du")?;
    if !out.status.success() {
        bail!("du failed for {}", dir.display());
    }
    String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .and_then(|n| n.parse::<u64>().ok())
        .context("parse du output")
}
