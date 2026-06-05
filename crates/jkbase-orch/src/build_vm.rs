//! Ephemeral build microVM lifecycle.
//!
//! A build VM runs *untrusted, attacker-controlled* code (`build.rs`,
//! `setup.py`, npm hooks, CNB `bin/build`), so unlike a runtime VM
//! ([`crate::vm`]) it is launched under the Firecracker **jailer**
//! ([`crate::jailer`]): chroot, drop to a dedicated non-root uid/gid, cgroup-v2
//! resource limits, a fresh PID namespace, and the built-in advanced seccomp
//! filter. One VM per build, destroyed on completion or timeout.
//!
//! STILL REQUIRED before this may run real tenant builds (tracked on the
//! Overboard `jkbase` board, tag `build`):
//!   - **Box verification** — every `// VERIFY(build/jailer):` marker here and
//!     in [`crate::jailer`] must be confirmed on a real KVM host (no CI/KVM in
//!     this repo). The OOM-kill containment test is a ship-blocker.
//!   - **Bounded console log** — the inherited `console.log` fd is currently
//!     unbounded (TODO below); a hostile guest can fill the host partition via
//!     `ttyS0` until it is capped/drained.
//!   - **cgroup provisioning** — `<cgroup_mount>/<parent_cgroup>` must exist
//!     with `+pids +memory +cpu` in `cgroup.subtree_control`, provisioned to
//!     survive reboot. A missing `memory` controller means `memory.max` never
//!     applies and a hostile guest drives *host* OOM.
//!   - **Egress** — no NIC is attached; the egress proxy + fetch-then-seal land
//!     before any networked build.
//!   - **In-guest build-runner** — the guest agent that runs the build and
//!     powers off on completion is a separate card; this spine treats "guest
//!     powered off within the timeout" as completion.

use crate::firecracker::{BootSource, Drive, FirecrackerClient, MachineConfig, VsockConfig};
use crate::jailer::{self, JailerConfig, JailerLayout};
use anyhow::{bail, Context, Result};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;
use tokio::process::{Child, Command};
use tracing::{error, info, warn};

/// Inputs for one ephemeral build VM. Read-only images (`toolchain_rootfs`,
/// `source_drive`, `kernel_path`) must already exist, be world-readable
/// (`0o444`), and live on the same filesystem as `chroot_base` (they are
/// hard-linked into the jail). The read-write scratch/output images are
/// preallocated inside the jail at the given sizes.
pub struct BuildVmConfig {
    pub jailer_bin: PathBuf,
    pub firecracker_bin: PathBuf,
    pub kernel_path: PathBuf,

    /// Read-only root device: the curated, content-addressed toolchain image.
    pub toolchain_rootfs: PathBuf,
    /// Read-only drive carrying the immutable source snapshot.
    pub source_drive: PathBuf,
    /// Size of the throwaway read-write scratch/overlay drive (preallocated).
    pub scratch_size_bytes: u64,
    /// Destination the output image is moved to (as raw bytes, never mounted)
    /// after the VM exits, for the build pipeline to validate.
    pub output_drive: PathBuf,
    /// Size of the (preallocated) read-write output drive.
    pub output_size_bytes: u64,
    /// Optional persistent per-project cache image. Moved into the jail for the
    /// build and moved back out afterwards.
    pub cache_drive: Option<PathBuf>,

    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    /// Guest CID for the log vsock (logs only — artifacts go via the output
    /// drive, not vsock).
    pub vsock_cid: Option<u32>,
    /// Hard wall-clock ceiling. Orthogonal to the cgroup limits: cgroups bound
    /// instantaneous resource use, this bounds total wall time.
    pub timeout: Duration,

    // --- containment ---
    /// `--chroot-base-dir`. Default `<data_dir>/jailer`; MUST be same-fs as the
    /// drive images.
    pub chroot_base: PathBuf,
    /// cgroup-v2 mount, default `/sys/fs/cgroup`.
    pub cgroup_mount: PathBuf,
    /// Dedicated non-root build uid/gid (default 100000).
    pub uid: u32,
    pub gid: u32,
    /// Root-owned parent cgroup whose ceilings the jailed uid cannot raise.
    pub parent_cgroup: String,
    pub cgroup_pids_max: u32,
    pub cgroup_mem_max_bytes: u64,
    /// cgroup-v2 `cpu.max` value, e.g. `"400000 100000"` (4 vCPU equiv).
    pub cgroup_cpu_max: String,
    /// Optional secondary output-size cap via `--resource-limit fsize=`.
    pub fsize_limit_bytes: Option<u64>,
    /// Console-log byte ceiling (enforcement is a TODO — see module docs).
    pub console_log_max_bytes: u64,
    /// Custom seccomp filter; `None` keeps firecracker's built-in advanced one.
    pub seccomp_filter: Option<PathBuf>,
    /// Network namespace; `None` → the build VM has no network at all.
    pub netns: Option<PathBuf>,
}

/// Why a build VM stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOutcome {
    /// The guest powered itself off within the timeout — the build ran to
    /// completion. Success vs failure is read later from the output drive.
    Completed,
    /// The wall-clock timeout tripped before the guest exited; the VM was
    /// force-killed. Billed for the minutes it consumed.
    TimedOut,
}

/// Host-side orchestrator for a single ephemeral, jailed build microVM.
pub struct BuildVm;

impl BuildVm {
    /// Stage drives into a fresh jail, boot the VM under the jailer, wait for it
    /// to finish (or hit the wall-clock timeout), then tear everything down. The
    /// jail (and its `mknod`'d device nodes) is removed on every exit path.
    pub async fn run(id: &str, config: &BuildVmConfig, runtime_dir: &Path) -> Result<BuildOutcome> {
        let id = jailer::sanitize_id(id)?;
        let layout = JailerLayout::new(
            &config.chroot_base,
            &config.cgroup_mount,
            &config.parent_cgroup,
            &id,
        );

        let result = Self::run_inner(&id, config, runtime_dir, &layout).await;
        // Teardown runs whether the build succeeded, errored, or timed out — and
        // is the real containment guarantee (see [`Self::teardown`]).
        Self::teardown(config, &layout).await;
        result
    }

    async fn run_inner(
        id: &str,
        config: &BuildVmConfig,
        runtime_dir: &Path,
        layout: &JailerLayout,
    ) -> Result<BuildOutcome> {
        // Hard-linking RO images into the jail requires same-fs.
        jailer::assert_same_fs(&config.chroot_base, &config.toolchain_rootfs)?;
        jailer::assert_same_fs(&config.chroot_base, &config.source_drive)?;
        jailer::assert_same_fs(&config.chroot_base, &config.kernel_path)?;

        // Stale-state hygiene: a prior crashed/killed build may have skipped
        // teardown. Clear the socket and the whole per-id tree before staging.
        if layout.host_socket.exists() {
            let _ = std::fs::remove_file(&layout.host_socket);
        }
        if layout.chroot_id_dir.exists() {
            let _ = std::fs::remove_dir_all(&layout.chroot_id_dir);
        }
        std::fs::create_dir_all(&layout.drives_dir)
            .with_context(|| format!("create {}", layout.drives_dir.display()))?;
        // Pre-create run/ so the host socket connect doesn't race the jailer.
        // VERIFY(build/jailer): jailer tolerates a pre-existing run/.
        std::fs::create_dir_all(layout.chroot_root.join("run"))?;

        // RO: kernel + toolchain + source, hard-linked (must be 0o444 at source).
        jailer::stage_ro(&config.kernel_path, &layout.chroot_root.join("kernel"))?;
        jailer::stage_ro(&config.toolchain_rootfs, &layout.drives_dir.join("rootfs.img"))?;
        jailer::stage_ro(&config.source_drive, &layout.drives_dir.join("source.img"))?;

        // RW: preallocated (non-sparse) so guest writes can't host-ENOSPC.
        jailer::stage_rw_prealloc(
            &layout.drives_dir.join("scratch.img"),
            config.scratch_size_bytes,
            config.uid,
            config.gid,
        )?;
        jailer::stage_rw_prealloc(
            &layout.drives_dir.join("output.img"),
            config.output_size_bytes,
            config.uid,
            config.gid,
        )?;
        if let Some(cache) = &config.cache_drive {
            jailer::assert_same_fs(&config.chroot_base, cache)?;
            // Move the persistent cache in (same-fs rename); moved back out in
            // teardown. VERIFY(build/jailer): cache image is preformatted/owned.
            std::fs::rename(cache, layout.drives_dir.join("cache.img"))
                .with_context(|| format!("move cache image {} into jail", cache.display()))?;
            jailer::chown_to(&layout.drives_dir.join("cache.img"), config.uid, config.gid)?;
        }

        // TODO(build/jailer) P0: console.log is an unbounded inherited fd — a
        // hostile guest can fill the host partition via ttyS0. Bound it (piped
        // drain capped at config.console_log_max_bytes) before untrusted builds.
        let log_path = runtime_dir.join(format!("{id}.console.log"));
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log_file =
            std::fs::File::create(&log_path).context("failed to create build VM console log")?;
        let stderr_log = log_file
            .try_clone()
            .context("failed to clone log file handle")?;

        let jcfg = Self::jailer_config(id, config);
        info!(id, log = %log_path.display(), "spawning build microVM via jailer");
        let mut process = Command::new(&config.jailer_bin)
            .args(jcfg.argv(layout))
            .stdout(Stdio::from(log_file))
            .stderr(Stdio::from(stderr_log))
            .kill_on_drop(true) // panic backstop; teardown is the real guarantee
            .spawn()
            .context("failed to spawn jailer for build VM")?;

        let outcome = Self::configure_and_wait(id, config, layout, &mut process).await;

        // Explicit reap of the jailer child; the cgroup liveness check in
        // teardown is what actually guarantees no escapee survives.
        let _ = process.start_kill();
        let _ = process.wait().await;
        outcome
    }

    fn jailer_config(id: &str, config: &BuildVmConfig) -> JailerConfig {
        let cgroups = vec![
            ("pids.max".to_string(), config.cgroup_pids_max.to_string()),
            ("memory.max".to_string(), config.cgroup_mem_max_bytes.to_string()),
            // No swap: a hostile build can't push host into swap thrash.
            ("memory.swap.max".to_string(), "0".to_string()),
            ("cpu.max".to_string(), config.cgroup_cpu_max.clone()),
        ];
        let resource_limits = config
            .fsize_limit_bytes
            .map(|b| vec![("fsize".to_string(), b.to_string())])
            .unwrap_or_default();
        JailerConfig {
            jailer_bin: config.jailer_bin.clone(),
            firecracker_bin: config.firecracker_bin.clone(),
            id: id.to_string(),
            uid: config.uid,
            gid: config.gid,
            chroot_base: config.chroot_base.clone(),
            parent_cgroup: config.parent_cgroup.clone(),
            cgroups,
            resource_limits,
            netns: config.netns.clone(),
        }
    }

    async fn configure_and_wait(
        id: &str,
        config: &BuildVmConfig,
        layout: &JailerLayout,
        process: &mut Child,
    ) -> Result<BuildOutcome> {
        wait_for_socket(&layout.host_socket, process).await?;
        // Host connects at the absolute socket path; firecracker's --api-sock
        // arg is the chroot-relative one — the two diverge under the jailer.
        let client = FirecrackerClient::new(&layout.host_socket);

        info!(id, "configuring build VM");
        client
            .set_machine_config(&MachineConfig {
                vcpu_count: config.vcpu_count,
                mem_size_mib: config.mem_size_mib,
            })
            .await?;
        client
            .set_boot_source(&BootSource {
                kernel_image_path: "kernel".to_string(),
                // No network args — the build VM has no NIC until egress lands.
                boot_args: "console=ttyS0 reboot=k panic=1 pci=off ro".to_string(),
            })
            .await?;

        // All paths are chroot-relative (inside drives/).
        client
            .set_drive(&Drive {
                drive_id: "rootfs".to_string(),
                path_on_host: layout.drive_rel("rootfs.img"),
                is_root_device: true,
                is_read_only: true,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "scratch".to_string(),
                path_on_host: layout.drive_rel("scratch.img"),
                is_root_device: false,
                is_read_only: false,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "source".to_string(),
                path_on_host: layout.drive_rel("source.img"),
                is_root_device: false,
                is_read_only: true,
            })
            .await?;
        client
            .set_drive(&Drive {
                drive_id: "output".to_string(),
                path_on_host: layout.drive_rel("output.img"),
                is_root_device: false,
                is_read_only: false,
            })
            .await?;
        if config.cache_drive.is_some() {
            client
                .set_drive(&Drive {
                    drive_id: "cache".to_string(),
                    path_on_host: layout.drive_rel("cache.img"),
                    is_root_device: false,
                    is_read_only: false,
                })
                .await?;
        }

        if let Some(cid) = config.vsock_cid {
            client
                .set_vsock(&VsockConfig {
                    guest_cid: cid,
                    uds_path: layout.vsock_arg.to_string(),
                })
                .await?;
        }

        info!(id, timeout_secs = config.timeout.as_secs(), "booting build VM");
        client.start().await?;

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

    /// Move artifacts out (raw bytes, never mounted), assert the cgroup is empty
    /// (force-killing any escapee), delete the jail, and alarm if anything —
    /// especially a `mknod`'d device node — survives. Best-effort but loud.
    async fn teardown(config: &BuildVmConfig, layout: &JailerLayout) {
        // Move the output image out as RAW BYTES before deleting the jail. It is
        // attacker-controlled ext4, so the extractor MUST NOT mount it or run
        // any ext4 userspace tool (mount/losetup/blkid/file/e2fsck) — threat
        // model P0-3. A plain same-fs rename touches no filesystem parser.
        let in_jail_output = layout.drives_dir.join("output.img");
        if in_jail_output.exists() {
            if let Some(parent) = config.output_drive.parent() {
                let _ = std::fs::create_dir_all(parent);
            }
            if let Err(e) = std::fs::rename(&in_jail_output, &config.output_drive) {
                warn!(error = %e, output = %config.output_drive.display(),
                      "failed to move build output image out of the jail");
            }
        }
        if let Some(cache) = &config.cache_drive {
            let in_jail_cache = layout.drives_dir.join("cache.img");
            if in_jail_cache.exists()
                && let Err(e) = std::fs::rename(&in_jail_cache, cache)
            {
                warn!(error = %e, cache = %cache.display(),
                      "failed to move build cache image back out of the jail");
            }
        }

        // Liveness assertion: rmdir of the leaf cgroup only succeeds when it is
        // empty. If not, the PID-ns collapse didn't reap everything — kill the
        // whole cgroup (cgroup-v2 `cgroup.kill`) and retry. Do NOT trust the
        // pidns collapse alone.
        if std::fs::remove_dir(&layout.cgroup_dir).is_err() && layout.cgroup_dir.exists() {
            warn!(cgroup = %layout.cgroup_dir.display(),
                  "build VM cgroup not empty after reap; force-killing");
            let _ = std::fs::write(layout.cgroup_dir.join("cgroup.kill"), "1");
            tokio::time::sleep(Duration::from_millis(200)).await;
            let _ = std::fs::remove_dir(&layout.cgroup_dir);
            if layout.cgroup_dir.exists() {
                error!(cgroup = %layout.cgroup_dir.display(),
                       "build VM cgroup STILL not reaped — possible escapee process");
            }
        }

        // Delete the jail: unlinks the RO hard links (shared inodes survive for
        // any concurrent jail), the preallocated RW images, and the mknod'd
        // device nodes (root unlinks; we never open() them).
        if let Err(e) = std::fs::remove_dir_all(&layout.chroot_id_dir) {
            warn!(error = %e, jail = %layout.chroot_id_dir.display(),
                  "failed to remove build VM jail");
        }

        // Device-node-leak alarm: a surviving `0o600 .../dev/kvm` is a standing
        // escape primitive, not a warning.
        if layout.chroot_id_dir.exists() {
            error!(jail = %layout.chroot_id_dir.display(),
                   "build VM jail NOT fully removed — possible leaked device node (escape primitive)");
        }
    }
}

/// Poll for the Firecracker API socket, but only return once it exists AND the
/// jailer is still alive — so we never connect to a stale socket and never hang
/// waiting on a process that already died.
async fn wait_for_socket(socket_path: &Path, process: &mut Child) -> Result<()> {
    // ~10s: the jailer's chroot setup is slower than a bare firecracker spawn.
    for _ in 0..100 {
        if let Some(status) = process.try_wait()? {
            bail!(
                "jailer/firecracker exited ({status}) before the API socket appeared; see console log"
            );
        }
        if socket_path.exists() {
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    bail!(
        "Firecracker API socket did not appear at {}",
        socket_path.display()
    )
}
