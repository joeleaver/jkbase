use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

/// Build the base rootfs image containing only the guest agent.
/// This is built once and reused across all projects.
pub async fn build_base_rootfs(agent_bin: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        info!(output = %output.display(), "base rootfs already exists, skipping build");
        return Ok(());
    }

    info!(output = %output.display(), "building base rootfs");

    let script = format!(
        r#"
set -euo pipefail
ROOTFS="{output}"
MOUNT_DIR=$(mktemp -d)
dd if=/dev/zero of="$ROOTFS" bs=1M count=32 status=none
mkfs.ext4 -F -q "$ROOTFS"
mount -o loop "$ROOTFS" "$MOUNT_DIR"

mkdir -p "$MOUNT_DIR"/{{sbin,dev,proc,sys,tmp,srv/www}}

cp "{agent}" "$MOUNT_DIR/sbin/init"
chmod +x "$MOUNT_DIR/sbin/init"

umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"
"#,
        output = output.display(),
        agent = agent_bin.display(),
    );

    run_sudo_script(&script).await?;

    info!(output = %output.display(), "base rootfs built");
    Ok(())
}

/// Build a content image containing only the static files for a project.
/// Small and fast to create — just the deployed files.
pub async fn build_content_image(content_dir: &Path, output: &Path) -> Result<()> {
    info!(output = %output.display(), "building content image");

    let script = format!(
        r#"
set -euo pipefail
IMAGE="{output}"

# Unmount stale loop mounts from a previous failed build
if losetup -j "$IMAGE" 2>/dev/null | grep -q .; then
    for mp in $(findmnt -rn -S "$IMAGE" -o TARGET 2>/dev/null); do
        umount "$mp" 2>/dev/null || true
        rmdir "$mp" 2>/dev/null || true
    done
    losetup -d $(losetup -j "$IMAGE" -O NAME -n 2>/dev/null) 2>/dev/null || true
fi

MOUNT_DIR=$(mktemp -d)

# Size the image to fit the content (minimum 4MB, 10% overhead for ext4 metadata)
CONTENT_SIZE_KB=$(du -sk "{content}/" | cut -f1)
OVERHEAD=$(( CONTENT_SIZE_KB / 10 ))
if [ "$OVERHEAD" -lt 4096 ]; then OVERHEAD=4096; fi
SIZE_KB=$(( CONTENT_SIZE_KB + OVERHEAD ))

dd if=/dev/zero of="$IMAGE" bs=1K count=$SIZE_KB status=none
mkfs.ext4 -F -q -m 0 -O ^has_journal "$IMAGE"
mount -o loop "$IMAGE" "$MOUNT_DIR"

cp -a "{content}"/. "$MOUNT_DIR/"

umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"
"#,
        output = output.display(),
        content = content_dir.display(),
    );

    run_sudo_script(&script).await?;

    info!(output = %output.display(), "content image built");
    Ok(())
}

/// Create a sparse data disk for persistent volumes. Only created once —
/// survives deploys, hibernation, and restarts. Destroyed on project delete.
pub async fn create_data_disk(output: &Path, size_mib: u32) -> Result<()> {
    if output.exists() {
        info!(output = %output.display(), "data disk already exists");
        return Ok(());
    }

    info!(output = %output.display(), size_mib, "creating sparse data disk");

    let script = format!(
        r#"
set -euo pipefail
IMAGE="{output}"
dd if=/dev/zero of="$IMAGE" bs=1M count=0 seek={size} status=none
mkfs.ext4 -F -q -m 1 "$IMAGE"
"#,
        output = output.display(),
        size = size_mib,
    );

    run_sudo_script(&script).await?;

    info!(output = %output.display(), "data disk created");
    Ok(())
}

async fn run_sudo_script(script: &str) -> Result<()> {
    let status = Command::new("sudo")
        .arg("bash")
        .arg("-c")
        .arg(script)
        .status()
        .await
        .context("failed to run build script")?;

    if !status.success() {
        anyhow::bail!("build script failed with status {status}");
    }

    Ok(())
}
