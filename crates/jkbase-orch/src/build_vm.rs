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
//!   - **cgroup provisioning** — `<cgroup_mount>/<parent_cgroup>` must exist
//!     with `+pids +memory +cpu` in `cgroup.subtree_control`, provisioned to
//!     survive reboot. A missing `memory` controller means `memory.max` never
//!     applies and a hostile guest drives *host* OOM.
//!   - **Egress** — no NIC is attached; the egress proxy + fetch-then-seal land
//!     before any networked build.
//!   - **In-guest build-runner** — the guest agent that runs the build and
//!     powers off on completion is a separate card; this spine treats "guest
//!     powered off within the timeout" as completion.

use crate::firecracker::{
    BootSource, Drive, FirecrackerClient, MachineConfig, NetworkInterface, VsockConfig,
};
use crate::jailer::{self, JailerConfig, JailerLayout};
use anyhow::{Context, Result, bail};
use std::future::Future;
use std::io::Write;
use std::os::unix::process::ExitStatusExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;
use tokio::io::AsyncReadExt;
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, Notify};

/// Host action that **seals** a build: tears down the network (deletes the TAP /
/// drops the route) so the COMPILE phase runs offline. Called once, on the
/// guest's fetch-complete console marker or at the fetch deadline — whichever is
/// first. Host-enforced: the guest has no API to bring the network back.
pub type SealFn = Box<dyn Fn() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send + Sync>;

/// Console marker the in-guest build-runner prints once dependency fetching is
/// done, signalling the host it may seal the network early (design §9).
pub const FETCH_COMPLETE_MARKER: &[u8] = b"[seal] FETCH-COMPLETE";

/// Console marker the in-guest build-runner prints just BEFORE
/// [`FETCH_COMPLETE_MARKER`], once it has flushed the cache drive (`sync`). The
/// seal-time cache capture ([`BuildVmConfig::persist_cache_from_seal`]) is only as
/// consistent as the image on disk: unflushed, ext4 delayed allocation can leave
/// extracted files empty behind a committed "unpacked" stamp, poisoning every later
/// build. No marker (an old toolchain, a force-sealed fetch) → no capture. A guest
/// that lies only corrupts its own project's cache.
pub const CACHE_SYNCED_MARKER: &[u8] = b"[seal] CACHE-SYNCED";
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
    /// build and moved back out afterwards (see `persist_cache_from_seal`).
    pub cache_drive: Option<PathBuf>,
    /// Persist the cache only as it stood AT THE SEAL (design §9 P2-7). The host
    /// pauses the VM at the seal, copies the cache image (raw sparse bytes, never
    /// parsed — P0-3), then seals and resumes; after the run that copy, never the
    /// live image, becomes the persistent cache. So nothing written while the build
    /// was offline — a dependency's `build.rs`, a proc-macro — can plant state (a
    /// `$CARGO_HOME` config, a git-db hook) that runs in a later build's network-up
    /// FETCH. A run that never sealed keeps its live image only if it was online the
    /// whole time. `false` → the live image always persists. Ignored without
    /// `cache_drive`.
    pub persist_cache_from_seal: bool,

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
    /// Process-wide `RLIMIT_FSIZE` (bytes) on Firecracker via `--resource-limit
    /// fsize=`. It bounds EVERY file FC writes — chiefly the RW drive backing
    /// files — so it MUST be >= the largest RW drive (scratch/output/cache), or a
    /// guest write past the limit's offset SIGXFSZ-kills the VM. It is not the
    /// build-artifact cap (that is the fixed output-drive size). `None` → unbounded.
    pub fsize_limit_bytes: Option<u64>,
    /// Console-log byte ceiling. Firecracker's stdout/stderr are piped (never an
    /// inherited fd) and drained into a byte-capped [`BoundedLog`]: past this many
    /// bytes output is discarded after a one-time marker, so a hostile guest
    /// spamming `ttyS0` can neither fill the host partition nor block on a full pipe.
    pub console_log_max_bytes: u64,
    /// Custom seccomp filter; `None` keeps firecracker's built-in advanced one.
    pub seccomp_filter: Option<PathBuf>,
    /// Network namespace; `None` → the build VM has no network at all.
    pub netns: Option<PathBuf>,

    // --- egress / fetch-then-seal (design §9) ---
    /// Host TAP the guest reaches the network through (the egress proxy). `None`
    /// → an offline build (single-phase). When set, the build is two-phase:
    /// FETCH (network up) → host-enforced SEAL (TAP torn down) → COMPILE (offline).
    pub tap_device: Option<String>,
    pub guest_mac: Option<String>,
    pub guest_ip: Option<String>,
    pub gateway_ip: Option<String>,
    /// Egress proxy URL exposed to the build (becomes `HTTP(S)_PROXY`), passed to
    /// the guest via the kernel cmdline (`jkbase.proxy=`).
    pub egress_proxy: Option<String>,
    /// Language hint (e.g. `"bun"`) for the in-VM lifecycle's detect, passed via
    /// the kernel cmdline (`jkbase.lang=`). `None` → the guest auto-detects.
    pub lang_hint: Option<String>,
    /// Request the layered artifact (content-addressed erofs layers + index.json)
    /// instead of the flat `rootfs.tar.gz` — passed as `jkbase.export=layered`.
    pub export_layered: bool,
    /// Build a WASM function (one `wasi:http` component → `/out/function.wasm`) instead
    /// of a server — passed as `jkbase.kind=function`. The in-VM lifecycle then runs the
    /// function-builder (language-dispatched) rather than the server buildpacks.
    pub build_function: bool,
    /// Build a STATIC site (a buildpack that produces a static tree, e.g. trunk →
    /// `dist/`) instead of a server — passed as `jkbase.kind=static`. The in-VM
    /// lifecycle runs the normal buildpack detect/build but exports a plain
    /// `/out/static.tar.gz` the host untars into the served site location. Mutually
    /// exclusive with `build_function`.
    pub build_static: bool,
    /// Build strategy override for the in-VM lifecycle's detect, passed via the
    /// kernel cmdline (`jkbase.builder=`). `Some("dockerfile")` forces the
    /// Dockerfile escape-hatch buildpack; `None` → normal language detection.
    pub builder_hint: Option<String>,
    /// Dockerfile path relative to the build subdir (the app_dir), passed via
    /// `jkbase.dockerfile=` when `builder = "dockerfile"`. `None` → the buildpack
    /// defaults to `Dockerfile`.
    pub dockerfile: Option<String>,
    /// Build SUBDIR within the mounted context (`/src`) where detect/build run, passed
    /// via `jkbase.build_subdir=`. `None` or `"."` → the build runs at the context root
    /// (today's behaviour). A non-`.` value is set when a monorepo `context` is mounted
    /// wider than the target's `source`, so `../sibling` path-deps resolve inside `/src`.
    pub build_subdir: Option<String>,
    /// Max wall-time the FETCH phase may hold the network before the host
    /// force-seals — even if the guest never signals fetch-complete (so a hostile
    /// build gets the network for at most this long).
    pub fetch_deadline: Duration,
    /// Host seal action (see [`SealFn`]). Ignored when `tap_device` is `None`.
    pub seal: Option<SealFn>,
}

/// Why a build VM stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BuildOutcome {
    /// The guest powered itself off within the timeout — the build ran to
    /// completion. Success vs failure is read later from the output drive.
    Completed,
    /// The VM died abnormally — firecracker exited non-zero or was signal-killed
    /// (e.g. a cgroup OOM-kill). The build did not complete; output is unusable.
    Crashed {
        code: Option<i32>,
        signal: Option<i32>,
    },
    /// The wall-clock timeout tripped before the guest exited; the VM was
    /// force-killed. Billed for the minutes it consumed.
    TimedOut,
}

/// One build VM run: its [`BuildOutcome`] plus resource usage captured at
/// teardown, for build-minute metering (design §8).
#[derive(Debug, Clone, Copy)]
pub struct BuildRun {
    pub outcome: BuildOutcome,
    /// Total CPU the build cgroup consumed (microseconds), from `cpu.stat` read
    /// just before the cgroup is reaped; `None` if unreadable.
    ///
    /// OBSERVABILITY ONLY — deliberately NOT the billing basis. The cgroup runs at
    /// `cpu.max = 400%`, so billing this charged a parallel build up to 4 quota-
    /// seconds per wall-second against a cap denominated in build-MINUTES. Bill
    /// [`Self::wall`] instead; the wall-clock timeout is what bounds a runaway build.
    pub cpu_usec: Option<u64>,
    /// Wall-clock from stage→exit (or timeout-kill), excluding teardown. THE BILLING
    /// BASIS: it starts before drive staging and boot, so every VM bills ≥1 s.
    pub wall: Duration,
}

/// Host-side orchestrator for a single ephemeral, jailed build microVM.
pub struct BuildVm;

impl BuildVm {
    /// Stage drives into a fresh jail, boot the VM under the jailer, wait for it
    /// to finish (or hit the wall-clock timeout), then tear everything down. The
    /// jail (and its `mknod`'d device nodes) is removed on every exit path.
    pub async fn run(id: &str, config: &BuildVmConfig, runtime_dir: &Path) -> Result<BuildRun> {
        let id = jailer::sanitize_id(id)?;
        // jailer names the chroot dir after the exec-file basename, not "firecracker".
        let exec_basename = config
            .firecracker_bin
            .file_name()
            .and_then(|s| s.to_str())
            .context("firecracker_bin has no valid UTF-8 file name")?;
        let layout = JailerLayout::new(
            &config.chroot_base,
            &config.cgroup_mount,
            &config.parent_cgroup,
            exec_basename,
            &id,
        );

        let started = std::time::Instant::now();
        let capture = std::sync::Mutex::new(SealCapture::NotReached);
        let result = Self::run_inner(&id, config, runtime_dir, &layout, &capture).await;
        let wall = started.elapsed();
        // Teardown runs whether the build succeeded, errored, or timed out — and
        // is the real containment guarantee (see [`Self::teardown`]). It also
        // reads the cgroup's total CPU before reaping it, for build metering.
        // A poisoned lock means a capture was in flight: fail closed.
        let capture = capture.into_inner().unwrap_or(SealCapture::Started);
        let cpu_usec = Self::teardown(config, &layout, capture).await;
        result.map(|outcome| BuildRun {
            outcome,
            cpu_usec,
            wall,
        })
    }

    async fn run_inner(
        id: &str,
        config: &BuildVmConfig,
        runtime_dir: &Path,
        layout: &JailerLayout,
        capture: &std::sync::Mutex<SealCapture>,
    ) -> Result<BuildOutcome> {
        // Hard-linking RO images into the jail requires same-fs.
        jailer::assert_same_fs(&config.chroot_base, &config.toolchain_rootfs)?;
        jailer::assert_same_fs(&config.chroot_base, &config.source_drive)?;
        jailer::assert_same_fs(&config.chroot_base, &config.kernel_path)?;

        // CONFIRMED (2026-06-05, jailer docs + on-box): pre-staging drive files
        // into the chroot BEFORE launching jailer is the correct pattern. Jailer
        // "does nothing if the path exists" and never clobbers staged files;
        // firecracker-go-sdk likewise hard-links resources in pre-launch. We
        // reference them by chroot-relative path once the socket appears.
        //
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
        jailer::stage_ro(
            &config.toolchain_rootfs,
            &layout.drives_dir.join("rootfs.img"),
        )?;
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

        // Bound the console log: a hostile guest can spam ttyS0 without limit, so
        // pipe firecracker's stdout/stderr and drain them into a byte-capped file
        // (config.console_log_max_bytes) rather than handing over an unbounded fd.
        // Past the ceiling, output is discarded with a one-time marker, so the
        // guest never blocks on a full pipe and never fills the host partition.
        let log_path = runtime_dir.join(format!("{id}.console.log"));
        if let Some(parent) = log_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let log_file =
            std::fs::File::create(&log_path).context("failed to create build VM console log")?;

        let jcfg = Self::jailer_config(id, config);
        info!(id, log = %log_path.display(), "spawning build microVM via jailer");
        let mut process = Command::new(&config.jailer_bin)
            .args(jcfg.argv(layout))
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true) // panic backstop; teardown is the real guarantee
            .spawn()
            .context("failed to spawn jailer for build VM")?;

        let log = Arc::new(Mutex::new(BoundedLog::new(
            log_file,
            config.console_log_max_bytes,
        )));
        // Notified when a console drain spots the fetch-complete marker, so the
        // host can seal the network early (see [`configure_and_wait`]). `synced`
        // records the cache-synced marker that gates the seal-time cache capture.
        let seal_notify = Arc::new(Notify::new());
        let synced = Arc::new(AtomicBool::new(false));
        let mut drains = Vec::new();
        if let Some(out) = process.stdout.take() {
            drains.push(tokio::spawn(drain_into(
                out,
                log.clone(),
                seal_notify.clone(),
                synced.clone(),
            )));
        }
        if let Some(err) = process.stderr.take() {
            drains.push(tokio::spawn(drain_into(
                err,
                log.clone(),
                seal_notify.clone(),
                synced.clone(),
            )));
        }

        let outcome = Self::configure_and_wait(
            id,
            config,
            layout,
            &mut process,
            seal_notify,
            &synced,
            capture,
        )
        .await;

        // Explicit reap of the jailer/firecracker child; the cgroup liveness
        // check in teardown is what actually guarantees no escapee survives.
        let _ = process.start_kill();
        let _ = process.wait().await;
        // Flush the console drains (the pipes close on exit → tasks finish).
        for d in drains {
            let _ = tokio::time::timeout(Duration::from_secs(2), d).await;
        }
        outcome
    }

    fn jailer_config(id: &str, config: &BuildVmConfig) -> JailerConfig {
        let cgroups = vec![
            ("pids.max".to_string(), config.cgroup_pids_max.to_string()),
            (
                "memory.max".to_string(),
                config.cgroup_mem_max_bytes.to_string(),
            ),
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
        seal_notify: Arc<Notify>,
        synced: &AtomicBool,
        capture: &std::sync::Mutex<SealCapture>,
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
        let mut boot_args = "console=ttyS0 reboot=k panic=1 pci=off ro".to_string();
        if let (Some(ip), Some(gw)) = (&config.guest_ip, &config.gateway_ip) {
            // Kernel IP autoconfig for the FETCH phase; the host seals the network
            // (deletes the TAP) before the guest's COMPILE phase.
            boot_args.push_str(&format!(" ip={ip}::{gw}:255.255.255.0::eth0:off"));
        }
        if config.tap_device.is_some() {
            // No IPv6 in build VMs: the egress proxy is IPv4-only, and an IPv6
            // link-local address would otherwise bypass the IPv4 build firewall
            // (host services + other build VMs over fe80::).
            boot_args.push_str(" ipv6.disable=1");
        }
        if let Some(proxy) = &config.egress_proxy {
            boot_args.push_str(&format!(" jkbase.proxy={proxy}"));
        }
        if let Some(lang) = &config.lang_hint
            && !lang.is_empty()
            && lang.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            // Safe token only (it lands verbatim on the kernel cmdline).
            boot_args.push_str(&format!(" jkbase.lang={lang}"));
        }
        if config.export_layered {
            boot_args.push_str(" jkbase.export=layered");
        }
        if config.build_function {
            boot_args.push_str(" jkbase.kind=function");
        } else if config.build_static {
            boot_args.push_str(" jkbase.kind=static");
        }
        if let Some(builder) = &config.builder_hint
            && !builder.is_empty()
            && builder
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            boot_args.push_str(&format!(" jkbase.builder={builder}"));
        }
        if let Some(df) = &config.dockerfile
            && is_safe_cmdline_path(df)
        {
            // Path token (may contain '/' and '.'); validated to stay a single,
            // shell-meta-free kernel cmdline token.
            boot_args.push_str(&format!(" jkbase.dockerfile={df}"));
        }
        if let Some(sub) = &config.build_subdir
            && sub != "."
            && is_safe_cmdline_path(sub)
        {
            // The build subdir within the mounted context. `"."` (build at context
            // root) is the default and emits nothing — identical to a non-monorepo
            // build. Same single-token / no-traversal guarantee as `dockerfile`.
            boot_args.push_str(&format!(" jkbase.build_subdir={sub}"));
        }
        client
            .set_boot_source(&BootSource {
                kernel_image_path: "kernel".to_string(),
                boot_args,
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

        if let (Some(tap), Some(mac)) = (&config.tap_device, &config.guest_mac) {
            client
                .set_network_interface(&NetworkInterface {
                    iface_id: "eth0".to_string(),
                    guest_mac: mac.clone(),
                    host_dev_name: tap.clone(),
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

        info!(
            id,
            timeout_secs = config.timeout.as_secs(),
            "booting build VM"
        );
        client.start().await?;

        // Fetch-then-seal: when a seal action is configured, the host tears the
        // network down once the guest signals fetch-complete (console marker) OR
        // at `fetch_deadline` — whichever first. The deadline is the hard cap, so
        // a hostile build gets the network for at most that long, even if it never
        // signals. Runs concurrently with the exit/timeout wait.
        let seal_fut = async {
            if config.seal.is_some() {
                tokio::select! {
                    _ = seal_notify.notified() => {
                        info!(id, "guest signalled fetch-complete; sealing network");
                    }
                    _ = tokio::time::sleep(config.fetch_deadline) => {
                        warn!(id, deadline_secs = config.fetch_deadline.as_secs(),
                              "fetch deadline reached; force-sealing network");
                    }
                }
                if let Some(seal) = &config.seal {
                    if config.persist_cache_from_seal && config.cache_drive.is_some() {
                        Self::seal_capturing_cache(
                            id, config, layout, &client, seal, synced, capture,
                        )
                        .await?;
                    } else {
                        seal().await;
                    }
                    info!(id, "build network sealed (compile runs offline)");
                }
            } else {
                std::future::pending::<()>().await;
            }
            anyhow::Ok(())
        };
        tokio::pin!(seal_fut);
        let exit = process.wait();
        tokio::pin!(exit);
        let timeout = tokio::time::sleep(config.timeout);
        tokio::pin!(timeout);
        let mut sealed = config.seal.is_none();

        loop {
            tokio::select! {
                res = &mut seal_fut, if !sealed => {
                    sealed = true;
                    res?;
                }
                status = &mut exit => {
                    let status = status.context("failed waiting on build VM process")?;
                    return Ok(if status.success() {
                        info!(id, "build VM exited cleanly (guest powered off)");
                        BuildOutcome::Completed
                    } else {
                        let (code, signal) = (status.code(), status.signal());
                        warn!(id, ?code, ?signal, "build VM died abnormally (crash / cgroup OOM-kill)");
                        BuildOutcome::Crashed { code, signal }
                    });
                }
                _ = &mut timeout => {
                    warn!(
                        id,
                        timeout_secs = config.timeout.as_secs(),
                        "build VM exceeded wall-clock timeout; killing"
                    );
                    return Ok(BuildOutcome::TimedOut);
                }
            }
        }
    }

    /// Seal, capturing the cache first (see [`BuildVmConfig::persist_cache_from_seal`]):
    /// pause → copy the cache image → seal → resume. The pause is what makes the
    /// copy exact rather than best-effort: no guest write lands mid-copy, and the
    /// guest can't observe the seal (so can't start COMPILE) until it resumes. The
    /// network is sealed on EVERY path — a failed or skipped capture only means
    /// nothing persists ([`SealCapture::Started`] → dropped at teardown).
    async fn seal_capturing_cache(
        id: &str,
        config: &BuildVmConfig,
        layout: &JailerLayout,
        client: &FirecrackerClient,
        seal: &SealFn,
        synced: &AtomicBool,
        capture: &std::sync::Mutex<SealCapture>,
    ) -> Result<()> {
        set_capture(capture, SealCapture::Started);
        let paused = match client.pause_vm().await {
            Ok(()) => true,
            Err(e) => {
                warn!(id, error = %e, "could not pause build VM at the seal; its cache will not persist");
                false
            }
        };
        if paused && let Some(cache) = &config.cache_drive {
            if !synced.load(Ordering::SeqCst) {
                // An old toolchain, or a fetch force-sealed at the deadline: the image
                // may hold unflushed (torn) state, so persisting it could break every
                // later build of this project. Start cold instead.
                warn!(
                    id,
                    "guest never reported a synced cache before the seal; it will not persist"
                );
            } else {
                let sealed = sealed_cache_path(cache);
                match copy_image_sparse(&layout.drives_dir.join("cache.img"), &sealed).await {
                    Ok(()) => set_capture(capture, SealCapture::Captured),
                    Err(e) => {
                        warn!(id, error = %e, "could not capture the build cache at the seal; it will not persist")
                    }
                }
            }
        }
        seal().await;
        if paused {
            client
                .resume_vm()
                .await
                .context("resume build VM after sealing")?;
        }
        Ok(())
    }

    /// Move artifacts out (raw bytes, never mounted), assert the cgroup is empty
    /// (force-killing any escapee), delete the jail, and alarm if anything —
    /// especially a `mknod`'d device node — survives. Best-effort but loud.
    async fn teardown(
        config: &BuildVmConfig,
        layout: &JailerLayout,
        capture: SealCapture,
    ) -> Option<u64> {
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
            let sealed = sealed_cache_path(cache);
            let keep = match cache_disposition(
                config.persist_cache_from_seal,
                config.tap_device.is_some(),
                capture,
            ) {
                CacheDisposition::KeepLive => Some(&in_jail_cache),
                CacheDisposition::KeepSealed => Some(&sealed),
                CacheDisposition::Drop => {
                    info!(cache = %cache.display(), ?capture,
                          "build cache not persisted (nothing captured at the seal); next build starts cold");
                    None
                }
            };
            if let Some(from) = keep
                && from.exists()
                && let Err(e) = std::fs::rename(from, cache)
            {
                warn!(error = %e, cache = %cache.display(), from = %from.display(),
                      "failed to persist the build cache image");
            }
            // Never leave a capture lying around for a later run to promote. (A
            // dropped live image goes with the jail below.)
            let _ = std::fs::remove_file(&sealed);
        }

        // Read the build cgroup's cumulative CPU (cpu.stat `usage_usec`) before it
        // is reaped below — observability only; billing is on `wall` (see `BuildRun`).
        let cpu_usec = read_cgroup_cpu_usec(&layout.cgroup_dir);

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

        cpu_usec
    }
}

/// Read a cgroup-v2 leaf's cumulative CPU time (`cpu.stat` `usage_usec`, in
/// microseconds). `None` if the controller/file is absent or unparseable.
fn read_cgroup_cpu_usec(cgroup_dir: &Path) -> Option<u64> {
    let stat = std::fs::read_to_string(cgroup_dir.join("cpu.stat")).ok()?;
    for line in stat.lines() {
        if let Some(v) = line.strip_prefix("usage_usec ") {
            return v.trim().parse().ok();
        }
    }
    None
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

/// A byte-capped writer for guest console output. Past the ceiling it discards
/// input (after a one-time marker), so a hostile guest spamming ttyS0 can
/// neither fill the host disk nor block on a full pipe.
struct BoundedLog<W: Write> {
    inner: W,
    remaining: u64,
    truncated: bool,
}

impl<W: Write> BoundedLog<W> {
    fn new(inner: W, max_bytes: u64) -> Self {
        Self {
            inner,
            remaining: max_bytes,
            truncated: false,
        }
    }

    fn write_chunk(&mut self, buf: &[u8]) -> std::io::Result<()> {
        if self.remaining == 0 {
            self.mark_truncated();
            return Ok(());
        }
        let n = self.remaining.min(buf.len() as u64) as usize;
        self.inner.write_all(&buf[..n])?;
        self.remaining -= n as u64;
        if self.remaining == 0 {
            self.mark_truncated();
        }
        Ok(())
    }

    fn mark_truncated(&mut self) {
        if !self.truncated {
            self.truncated = true;
            let _ = self
                .inner
                .write_all(b"\n[console log truncated: byte ceiling reached]\n");
        }
    }
}

/// Drain a child stdout/stderr stream into the shared, byte-capped console log,
/// and notify `seal` the first time the [`FETCH_COMPLETE_MARKER`] appears (so the
/// host can seal the network early). A [`CACHE_SYNCED_MARKER`] seen before it sets
/// `synced`. A small rolling window catches a marker even when it straddles two
/// reads.
async fn drain_into<R: tokio::io::AsyncRead + Unpin>(
    mut reader: R,
    log: Arc<Mutex<BoundedLog<std::fs::File>>>,
    seal: Arc<Notify>,
    synced: Arc<AtomicBool>,
) {
    let mut buf = [0u8; 8192];
    let mut scan = MarkerScan::default();
    loop {
        match reader.read(&mut buf).await {
            Ok(0) | Err(_) => break,
            Ok(n) => {
                {
                    let mut guard = log.lock().await;
                    let _ = guard.write_chunk(&buf[..n]);
                }
                let (saw_synced, saw_complete) = scan.feed(&buf[..n]);
                // `synced` is stored BEFORE the seal is notified: the guest prints the
                // two markers back to back, often in one read, and the seal task reads
                // the flag as soon as it wakes.
                if saw_synced {
                    synced.store(true, Ordering::SeqCst);
                }
                if saw_complete {
                    // notify_one stores a permit if the seal task isn't yet
                    // waiting, so the wakeup is never lost.
                    seal.notify_one();
                }
            }
        }
    }
}

/// Rolling scan of the guest console for the seal markers. Each chunk is searched
/// together with the tail of the previous one BEFORE trimming, so a marker is found
/// whether it straddles two reads or sits anywhere inside one large read.
#[derive(Default)]
struct MarkerScan {
    tail: Vec<u8>,
    synced: bool,
    fired: bool,
}

impl MarkerScan {
    /// Feed one read; returns `(newly saw CACHE_SYNCED, newly saw FETCH_COMPLETE)`.
    /// Scanning stops after FETCH_COMPLETE — a synced marker printed after the seal
    /// has already fired is too late to matter and is ignored.
    fn feed(&mut self, chunk: &[u8]) -> (bool, bool) {
        if self.fired {
            return (false, false);
        }
        self.tail.extend_from_slice(chunk);
        let has = |hay: &[u8], m: &[u8]| hay.windows(m.len()).any(|w| w == m);
        let saw_synced = !self.synced && has(&self.tail, CACHE_SYNCED_MARKER);
        self.synced |= saw_synced;
        let saw_complete = has(&self.tail, FETCH_COMPLETE_MARKER);
        self.fired = saw_complete;
        let keep = FETCH_COMPLETE_MARKER.len().max(CACHE_SYNCED_MARKER.len());
        if self.tail.len() > keep {
            self.tail.drain(..self.tail.len() - keep);
        }
        (saw_synced, saw_complete)
    }
}

/// Progress of the seal-time cache capture ([`BuildVmConfig::persist_cache_from_seal`]),
/// written by the seal and read at teardown.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SealCapture {
    /// The seal never began: the VM was online for its whole life.
    NotReached,
    /// The seal began but no usable copy exists (pause/copy failed, the guest never
    /// reported a synced cache, or the run died mid-capture).
    Started,
    /// The cache image as of the seal was copied beside the persistent path.
    Captured,
}

/// What teardown does with the cache image.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CacheDisposition {
    /// Move the live (in-jail) image back.
    KeepLive,
    /// Promote the copy taken at the seal; the live image goes with the jail.
    KeepSealed,
    /// Persist nothing; the next build starts from an empty cache.
    Drop,
}

/// The persistence rule, as a pure function so the table is testable. With
/// `persist_from_seal`, only state written while the VM was ONLINE may persist.
fn cache_disposition(
    persist_from_seal: bool,
    networked: bool,
    capture: SealCapture,
) -> CacheDisposition {
    match (persist_from_seal, capture) {
        (false, _) => CacheDisposition::KeepLive,
        (true, SealCapture::Captured) => CacheDisposition::KeepSealed,
        (true, SealCapture::Started) => CacheDisposition::Drop,
        // Never sealed: a networked VM was online until it exited, so everything in
        // the live image was written online. An offline VM never was — nothing
        // qualifies.
        (true, SealCapture::NotReached) if networked => CacheDisposition::KeepLive,
        (true, SealCapture::NotReached) => CacheDisposition::Drop,
    }
}

fn set_capture(capture: &std::sync::Mutex<SealCapture>, to: SealCapture) {
    if let Ok(mut c) = capture.lock() {
        *c = to;
    }
}

/// Where the seal-time copy of `cache` is written: beside it, on the same fs as the
/// jail but outside it, so the jailed VMM can't reach it.
fn sealed_cache_path(cache: &Path) -> PathBuf {
    let mut name = cache.file_name().unwrap_or_default().to_os_string();
    name.push(".sealed");
    cache.with_file_name(name)
}

/// Copy a guest-written image as raw bytes, keeping it sparse. `cp` never interprets
/// the contents, so this stays inside threat-model P0-3 (the host never parses a
/// guest filesystem). Killed if the caller is dropped (e.g. the build timed out).
async fn copy_image_sparse(from: &Path, to: &Path) -> Result<()> {
    let status = Command::new("cp")
        .arg("--sparse=always")
        .arg("--")
        .arg(from)
        .arg(to)
        .kill_on_drop(true)
        .status()
        .await
        .context("spawn cp")?;
    if !status.success() {
        bail!("cp {} -> {}: {status}", from.display(), to.display());
    }
    Ok(())
}

/// A path is safe to land verbatim on the kernel cmdline (as `jkbase.dockerfile=`
/// or `jkbase.build_subdir=`) iff it is a single token of path-y characters only:
/// alphanumerics plus `._-/`, non-empty, no leading `/` or `-`, and no `..`
/// traversal. Anything else (spaces, quotes, shell metacharacters) is rejected so it
/// cannot inject extra cmdline tokens. Shared so the orchestrator can reject such a
/// path at deploy time (`validate_manifest`) rather than silently dropping the token
/// here and building at the wrong dir — the two checks must use the same predicate.
pub fn is_safe_cmdline_path(p: &str) -> bool {
    !p.is_empty()
        && !p.starts_with('/')
        && !p.starts_with('-')
        && !p.contains("..")
        && p.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-' | '/'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn safe_cmdline_path_accepts_paths_rejects_injection() {
        assert!(is_safe_cmdline_path("Dockerfile"));
        assert!(is_safe_cmdline_path("docker/Dockerfile"));
        assert!(is_safe_cmdline_path("svc/api.Dockerfile"));
        assert!(!is_safe_cmdline_path("")); // empty
        assert!(!is_safe_cmdline_path("/etc/passwd")); // absolute
        assert!(!is_safe_cmdline_path("../escape/Dockerfile")); // traversal
        assert!(!is_safe_cmdline_path("a b/Dockerfile")); // space => extra token
        assert!(!is_safe_cmdline_path("Dockerfile;rm -rf")); // shell meta
        assert!(!is_safe_cmdline_path("-rf")); // leading dash => flag
    }

    #[test]
    fn bounded_log_caps_and_marks_once() {
        let mut buf: Vec<u8> = Vec::new();
        {
            let mut bl = BoundedLog::new(&mut buf, 10);
            bl.write_chunk(b"hello").unwrap(); // 5 / 10
            bl.write_chunk(b"WORLD!!!").unwrap(); // 5 more -> hits cap + marker
            bl.write_chunk(b"discarded").unwrap(); // dropped
        }
        let s = String::from_utf8(buf).unwrap();
        assert!(s.starts_with("helloWORLD"), "got {s:?}");
        assert!(s.contains("truncated"));
        assert!(!s.contains("discarded"));
        assert_eq!(s.matches("truncated").count(), 1, "marker written once");
    }

    #[test]
    fn cache_disposition_persists_only_state_written_online() {
        use CacheDisposition::*;
        use SealCapture::*;
        // Legacy mode: the live image always goes back.
        for c in [NotReached, Started, Captured] {
            assert_eq!(cache_disposition(false, true, c), KeepLive);
            assert_eq!(cache_disposition(false, false, c), KeepLive);
        }
        // Seal mode: only the seal-time copy, or a VM that was online throughout.
        assert_eq!(cache_disposition(true, true, Captured), KeepSealed);
        assert_eq!(cache_disposition(true, true, Started), Drop);
        assert_eq!(cache_disposition(true, true, NotReached), KeepLive);
        assert_eq!(cache_disposition(true, false, NotReached), Drop);
        assert_eq!(cache_disposition(true, false, Started), Drop);
    }

    #[test]
    fn marker_scan_finds_markers_within_and_across_reads() {
        // Both markers in one large read, with plenty of output after them — the
        // window must not trim them away before scanning.
        let mut s = MarkerScan::default();
        let mut chunk = b"noise\n".repeat(10);
        chunk.extend_from_slice(b"[seal] CACHE-SYNCED\n[seal] FETCH-COMPLETE\n");
        chunk.extend(b"after\n".repeat(200));
        assert_eq!(s.feed(&chunk), (true, true));
        assert_eq!(
            s.feed(b"[seal] FETCH-COMPLETE"),
            (false, false),
            "fires once"
        );

        // Each marker split across two reads.
        let mut s = MarkerScan::default();
        assert_eq!(s.feed(b"xx[seal] CACHE-SY"), (false, false));
        assert_eq!(s.feed(b"NCED\n[seal] FETCH-"), (true, false));
        assert_eq!(s.feed(b"COMPLETE\n"), (false, true));

        // Old guest: fetch-complete with no synced marker.
        let mut s = MarkerScan::default();
        assert_eq!(s.feed(b"[seal] FETCH-COMPLETE\n"), (false, true));
        assert!(!s.synced);

        // Synced reported once even if repeated.
        let mut s = MarkerScan::default();
        assert_eq!(s.feed(b"[seal] CACHE-SYNCED\n"), (true, false));
        assert_eq!(s.feed(b"[seal] CACHE-SYNCED\n"), (false, false));
    }

    #[test]
    fn sealed_cache_path_sits_beside_the_cache() {
        assert_eq!(
            sealed_cache_path(Path::new("/var/jkbase/buildcache/p/rust.img")),
            PathBuf::from("/var/jkbase/buildcache/p/rust.img.sealed")
        );
    }

    #[tokio::test]
    async fn copy_image_sparse_keeps_bytes_and_holes() {
        use std::io::{Seek, SeekFrom};
        use std::os::unix::fs::MetadataExt;
        let dir = std::env::temp_dir().join(format!("jkb-cache-copy-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let (from, to) = (dir.join("cache.img"), dir.join("cache.img.sealed"));

        // 64 MiB sparse image with data at the start and deep inside.
        let mut f = std::fs::File::create(&from).unwrap();
        f.set_len(64 << 20).unwrap();
        f.write_all(b"head").unwrap();
        f.seek(SeekFrom::Start(40 << 20)).unwrap();
        f.write_all(b"deep").unwrap();
        drop(f);
        std::fs::write(&to, b"stale capture").unwrap(); // overwritten, not appended

        copy_image_sparse(&from, &to).await.unwrap();
        let (a, b) = (std::fs::read(&from).unwrap(), std::fs::read(&to).unwrap());
        assert_eq!(a, b, "byte-identical copy");
        let allocated = std::fs::metadata(&to).unwrap().blocks() * 512;
        assert!(
            allocated < 1 << 20,
            "copy stayed sparse ({allocated} bytes allocated)"
        );

        assert!(
            copy_image_sparse(&dir.join("missing.img"), &to)
                .await
                .is_err()
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
