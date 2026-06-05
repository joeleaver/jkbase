//! Ephemeral build microVM lifecycle.
//!
//! A build VM is fundamentally different from a runtime VM ([`crate::vm`]): it
//! runs *untrusted, attacker-controlled* code (`build.rs`, `setup.py`, npm
//! hooks, CNB `bin/build`), so it must be sandboxed as hard as the runtime and
//! it is **throwaway** — one VM per build, destroyed on completion or timeout.
//!
//! This module owns the host-side lifecycle spine: spawn → multi-drive layout →
//! boot → wait-for-completion-or-timeout → guaranteed teardown. The build VM is
//! deliberately built as a *separate* path from [`crate::vm::VmInstance`] so the
//! runtime path is untouched while the hardening below is still missing.
//!
//! NOT YET IMPLEMENTED (tracked on the Overboard `jkbase` board, tag `build`):
//!   - **Hardening** — spawn via the Firecracker `jailer` (chroot + cgroup-v2
//!     `pids`/`memory.max`/`cpu` + seccomp + non-root uid/gid). Until this
//!     lands, a build VM MUST NOT be given a real tenant build to run.
//!   - **Egress** — no network interface is attached here; the default-deny
//!     egress proxy + host-enforced fetch-then-seal are separate cards.
//!   - **Output handling** — the output drive is read by the host *after*
//!     teardown as a content-addressed stream, never mounted live with the host
//!     kernel (threat-model P0-3). Validation lives in the build pipeline.
//!   - **In-guest build-runner** — the guest agent that actually runs the build
//!     and powers the VM off when done is a separate card; this spine treats
//!     "guest powered off within the timeout" as build completion.

use crate::firecracker::{BootSource, Drive, FirecrackerClient, MachineConfig, VsockConfig};
use anyhow::{Context, Result};
use std::path::{Path, PathBuf};
use std::time::Duration;
use tokio::process::{Child, Command};
use tracing::{info, warn};

/// Drive layout for a build VM. All paths are host paths to backing images.
///
/// The toolchain rootfs is the read-only root device; everything the build
/// mutates lives on the writable scratch drive (a throwaway overlay/CoW area),
/// so the multi-GB toolchain image is never re-`mkfs`'d per build.
pub struct BuildVmConfig {
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,
    /// Read-only root device: the curated, content-addressed toolchain image.
    pub toolchain_rootfs: PathBuf,
    /// Writable scratch/overlay drive (throwaway — destroyed with the VM).
    pub scratch_drive: PathBuf,
    /// Read-only drive carrying the immutable source snapshot.
    pub source_drive: PathBuf,
    /// Writable drive the guest writes artifacts to. The host reads it only
    /// *after* teardown, as a validated content-addressed stream — never
    /// mounted live with the host kernel (threat-model P0-3).
    pub output_drive: PathBuf,
    /// Optional writable per-project dependency cache drive.
    pub cache_drive: Option<PathBuf>,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    /// Guest CID for the log vsock (logs only — bulk artifacts go via the
    /// output drive, not vsock).
    pub vsock_cid: Option<u32>,
    /// Hard wall-clock ceiling. The host force-kills the VM if the build runs
    /// longer — fork-bomb / never-terminating-build backstop.
    pub timeout: Duration,
}

/// Why a build VM stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOutcome {
    /// The guest powered itself off within the timeout — the build ran to
    /// completion. Success vs failure is determined later from the output
    /// drive, not from this signal.
    Completed,
    /// The wall-clock timeout tripped before the guest exited; the VM was
    /// force-killed. Billed for the minutes it consumed.
    TimedOut,
}

/// Host-side orchestrator for a single ephemeral build microVM.
pub struct BuildVm;

impl BuildVm {
    /// Boot a throwaway build VM, wait for it to finish (or hit the wall-clock
    /// timeout), and tear it down. The Firecracker process is killed and the
    /// per-VM runtime directory removed on every exit path, including errors.
    pub async fn run(id: &str, config: &BuildVmConfig, runtime_dir: &Path) -> Result<BuildOutcome> {
        let vm_dir = runtime_dir.join(id);
        tokio::fs::create_dir_all(&vm_dir)
            .await
            .context("failed to create build VM runtime directory")?;

        let socket_path = vm_dir.join("firecracker.sock");
        let _ = tokio::fs::remove_file(&socket_path).await;

        let vsock_path = config.vsock_cid.map(|_| vm_dir.join("vsock.sock"));
        if let Some(ref vp) = vsock_path {
            let _ = tokio::fs::remove_file(vp).await;
        }

        let log_path = vm_dir.join("console.log");
        let log_file =
            std::fs::File::create(&log_path).context("failed to create build VM console log")?;
        let stderr_log = log_file
            .try_clone()
            .context("failed to clone log file handle")?;

        // TODO(build/Harden orch): spawn via the Firecracker `jailer` binary
        // (chroot + cgroup-v2 pids/memory.max/cpu + seccomp + drop to a
        // non-root uid/gid), NOT `firecracker` directly. `kill_on_drop` is the
        // safety net so a panic between here and teardown still reaps the VM.
        info!(id, log = %log_path.display(), "spawning build microVM");
        let mut process = Command::new(&config.firecracker_bin)
            .arg("--api-sock")
            .arg(&socket_path)
            .stdout(std::process::Stdio::from(log_file))
            .stderr(std::process::Stdio::from(stderr_log))
            .kill_on_drop(true)
            .spawn()
            .context("failed to spawn Firecracker process for build VM")?;

        // Run the build behind a guaranteed teardown: whatever the result, kill
        // the process and remove the throwaway runtime dir before returning.
        let result = Self::configure_and_wait(
            id,
            config,
            &socket_path,
            vsock_path.as_deref(),
            &mut process,
        )
        .await;

        let _ = process.start_kill();
        let _ = process.wait().await;
        let _ = tokio::fs::remove_dir_all(&vm_dir).await;

        result
    }

    async fn configure_and_wait(
        id: &str,
        config: &BuildVmConfig,
        socket_path: &Path,
        vsock_path: Option<&Path>,
        process: &mut Child,
    ) -> Result<BuildOutcome> {
        wait_for_socket(socket_path).await?;
        let client = FirecrackerClient::new(socket_path);

        info!(id, "configuring build VM");
        client
            .set_machine_config(&MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.mem_size_mib,
            })
            .await?;

        client
            .set_boot_source(&BootSource {
                kernel_image_path: config.kernel_path.to_string_lossy().to_string(),
                // No network args: a build VM gets no NIC until the egress
                // proxy + fetch-then-seal land.
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".to_string(),
            })
            .await?;

        // Root = the read-only toolchain image. Everything the build writes goes
        // to the throwaway scratch drive, so the toolchain image is shared,
        // read-only, and never rewritten per build.
        client
            .set_drive(&Drive {
                drive_id: "rootfs".to_string(),
                path_on_host: config.toolchain_rootfs.to_string_lossy().to_string(),
                is_root_device: true,
                is_read_only: true,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "scratch".to_string(),
                path_on_host: config.scratch_drive.to_string_lossy().to_string(),
                is_root_device: false,
                is_read_only: false,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "source".to_string(),
                path_on_host: config.source_drive.to_string_lossy().to_string(),
                is_root_device: false,
                is_read_only: true,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "output".to_string(),
                path_on_host: config.output_drive.to_string_lossy().to_string(),
                is_root_device: false,
                is_read_only: false,
            })
            .await?;
        if let Some(cache) = &config.cache_drive {
            client
                .set_drive(&Drive {
                    drive_id: "cache".to_string(),
                    path_on_host: cache.to_string_lossy().to_string(),
                    is_root_device: false,
                    is_read_only: false,
                })
                .await?;
        }

        if let (Some(cid), Some(vp)) = (config.vsock_cid, vsock_path) {
            client
                .set_vsock(&VsockConfig {
                    guest_cid: cid,
                    uds_path: vp.to_string_lossy().to_string(),
                })
                .await?;
        }

        info!(id, timeout_secs = config.timeout.as_secs(), "booting build VM");
        client.start().await?;

        // Host-enforced wall-clock ceiling. The guest powers itself off when the
        // build finishes (Firecracker process exits); if it doesn't within the
        // budget, the timeout fires and the caller's teardown force-kills it.
        match tokio::time::timeout(config.timeout, process.wait()).await {
            Ok(status) => {
                let status = status.context("failed waiting on build VM process")?;
                info!(id, ?status, "build VM exited");
                Ok(BuildOutcome::Completed)
            }
            Err(_elapsed) => {
                warn!(
                    id,
                    timeout_secs = config.timeout.as_secs(),
                    "build VM exceeded wall-clock timeout; killing"
                );
                Ok(BuildOutcome::TimedOut)
            }
        }
    }
}

/// Poll for the Firecracker API socket to appear (up to ~5s), mirroring the
/// runtime VM path.
async fn wait_for_socket(socket_path: &Path) -> Result<()> {
    for _ in 0..50 {
        if socket_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    anyhow::bail!(
        "Firecracker socket did not appear at {}",
        socket_path.display()
    )
}
