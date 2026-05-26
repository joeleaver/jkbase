use anyhow::{Context, Result};
use std::path::Path;
use tokio::process::Command;
use tracing::info;

pub async fn build_rootfs(
    agent_bin: &Path,
    content_dir: &Path,
    output: &Path,
    size_mb: u32,
) -> Result<()> {
    info!(output = %output.display(), "building rootfs");

    let script = format!(
        r#"
set -euo pipefail
ROOTFS="{output}"
MOUNT_DIR=$(mktemp -d)
dd if=/dev/zero of="$ROOTFS" bs=1M count={size_mb} status=none
mkfs.ext4 -F -q "$ROOTFS"
mount -o loop "$ROOTFS" "$MOUNT_DIR"

mkdir -p "$MOUNT_DIR"/{{sbin,dev,proc,sys,tmp,srv/www}}

cp "{agent}" "$MOUNT_DIR/sbin/init"
chmod +x "$MOUNT_DIR/sbin/init"

cp -r "{content}"/. "$MOUNT_DIR/srv/www/"

umount "$MOUNT_DIR"
rmdir "$MOUNT_DIR"
"#,
        output = output.display(),
        size_mb = size_mb,
        agent = agent_bin.display(),
        content = content_dir.display(),
    );

    let status = Command::new("sudo")
        .arg("bash")
        .arg("-c")
        .arg(&script)
        .status()
        .await
        .context("failed to run rootfs build script")?;

    if !status.success() {
        anyhow::bail!("rootfs build failed with status {status}");
    }

    info!(output = %output.display(), "rootfs built");
    Ok(())
}
