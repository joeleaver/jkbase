use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use tokio::process::Command;
use tracing::info;

/// Build the runtime VM rootfs — an apko Wolfi (glibc) userland + chrony with the
/// guest agent injected as `/sbin/init` — by invoking `tools/build-runtime-rootfs.sh`
/// (userspace `mkfs.ext4 -d`, no mount, no sudo). chrony lets the agent discipline
/// the guest wall clock from the KVM PTP device; the userland is why this is no
/// longer a single hand-staged static binary.
///
/// Built once and reused read-only across all projects. In production the artifact
/// is prebuilt at deploy/provision time (where apko is on the deploy user's PATH),
/// so this skips; the build path here is a local-dev fallback and needs apko.
pub async fn build_base_rootfs(agent_bin: &Path, output: &Path) -> Result<()> {
    if output.exists() {
        info!(output = %output.display(), "base rootfs already exists, skipping build");
        return Ok(());
    }

    let script = locate_build_script(agent_bin).with_context(|| {
        "could not find tools/build-runtime-rootfs.sh next to the agent binary; \
         prebuild the runtime rootfs (tools/build-runtime-rootfs.sh) or run via tools/dev"
    })?;

    info!(
        output = %output.display(),
        script = %script.display(),
        "building base rootfs via apko"
    );
    let status = Command::new("bash")
        .arg(&script)
        .env("AGENT_BIN", agent_bin)
        .env("OUT", output)
        .status()
        .await
        .context("failed to run build-runtime-rootfs.sh")?;
    if !status.success() {
        anyhow::bail!(
            "build-runtime-rootfs.sh failed ({status}); is apko installed? \
             (run tools/install-image-tools.sh)"
        );
    }

    info!(output = %output.display(), "base rootfs built");
    Ok(())
}

/// Walk up from the agent binary (`<repo>/target/<triple>/release/jkbase-agent`) to
/// find the repo's `tools/build-runtime-rootfs.sh`.
fn locate_build_script(agent_bin: &Path) -> Option<PathBuf> {
    let mut dir = agent_bin.parent();
    while let Some(d) = dir {
        let candidate = d.join("tools").join("build-runtime-rootfs.sh");
        if candidate.is_file() {
            return Some(candidate);
        }
        dir = d.parent();
    }
    None
}
