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

mkdir -p "$MOUNT_DIR"/{{sbin,dev,proc,sys,tmp,srv/www,mnt/data}}

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
