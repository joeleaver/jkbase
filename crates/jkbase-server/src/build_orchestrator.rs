//! Server-side build orchestration: the per-target fan-out above jkbase-orch's
//! `BuildVm` primitive (design §4/§12).
//!
//! `POST /build` (jkbase-control) hands us an uploaded source tarball via the
//! `build_callback`. We unpack it, read `jkbase.toml`, assemble the non-build
//! artifacts (route/site/domain/schedule sidecars + static site content), then
//! fan out **one ephemeral jailed build VM per server and per function**, each
//! with its own content-addressed toolchain image, building in parallel. Each VM
//! emits its artifact to a write-only output drive that we read back WITHOUT
//! mounting (debugfs; threat-model P0-3). On success we return the fully-
//! assembled artifact directory for jkbase-control's unchanged deploy tail —
//! **atomically**: any target's failure fails the whole build and nothing is
//! activated, matching `do_deploy`'s atomic symlink swap.
//!
//! ## Output-drive contract (what a build VM writes to `/out`)
//! - `/out/status`     — the build's exit code (the build-runner writes this).
//! - `/out/build.log`  — captured build log.
//! - function target → `/out/function.wasm`.
//! - server target   → `/out/rootfs.tar.gz` (+ optional `/out/manifest.json`
//!   carrying build-derived `cmd`/`env`/`working_dir`).
//!
//! The toolchain image is generic (it runs the source's build); only these
//! output names are contract. Richer toolchains (CNB for servers,
//! cargo-component for functions) are B2 and keep this contract unchanged.

use anyhow::{bail, Context, Result};
use jkbase_common::config::ProjectConfig;
use jkbase_control::store::{BuildPhase, BuildTargetStatus, Store, TargetKind};
use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig, SealFn};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::{Mutex, Semaphore};
use tracing::{info, warn};

const EXCLUDED_FILES: &[&str] = &["jkbase.toml", "Dockerfile"];
const EXCLUDED_DIRS: &[&str] = &["node_modules", ".git", "target"];
/// Combined build-log tail kept in the build record (per-target logs concatenated).
const LOG_TAIL_CAP: usize = 64 * 1024;
/// Per-target log slice pulled from the output drive into the record.
const TARGET_LOG_CAP: usize = 16 * 1024;

/// Immutable per-server build configuration, built once at startup and shared by
/// every build job. Paths hard-linked into the jail (kernel, toolchain images,
/// source images) MUST live on the same filesystem as `data_dir` and be
/// world-readable; the orchestrator and `build_ro_ext4_from_dir` guarantee perms.
pub struct BuildDeps {
    pub jailer_bin: PathBuf,
    pub firecracker_bin: PathBuf,
    /// Kernel staged onto the data-dir filesystem (same-fs hard-link + 0o444).
    pub kernel_path: PathBuf,
    pub data_dir: PathBuf,
    /// `{data_dir}/hosting` — deploy artifacts; staging output lands here so the
    /// activate step's rename into `deployments/v{N}` is a same-fs move.
    pub deploy_dir: PathBuf,
    /// Directory of content-addressed toolchain images (`default.ext4`, or
    /// per-language `{language}.ext4` / per-kind `{function,server}.ext4`).
    pub toolchain_dir: PathBuf,
    pub store: Store,
    // -- containment / tuning --
    pub chroot_base: PathBuf,
    pub cgroup_mount: PathBuf,
    pub parent_cgroup: String,
    pub uid: u32,
    pub gid: u32,
    pub timeout: Duration,
    pub vcpu_count: u32,
    pub mem_size_mib: u32,
    pub cgroup_pids_max: u32,
    pub cgroup_mem_max_bytes: u64,
    pub cgroup_cpu_max: String,
    pub scratch_size_bytes: u64,
    pub output_size_bytes: u64,
    pub console_log_max_bytes: u64,
    /// Max build VMs booting concurrently across all jobs.
    pub max_concurrent: usize,
    /// Isolated build network for dependency fetches; `None` → offline builds.
    pub net: Option<Arc<BuildNet>>,
    /// Max time the FETCH phase may hold the network before the host force-seals.
    pub fetch_deadline: Duration,
}

impl BuildDeps {
    /// Select the toolchain image for a target. Precedence: the per-language
    /// jkbuild image (`{language}.ext4`, e.g. `bun.ext4`), then the jkbuild
    /// per-kind image (`jkbuild-{kind}.ext4`), then a legacy per-kind image, then
    /// the busybox passthrough `default.ext4`.
    fn select_toolchain(&self, kind: TargetKind, language: Option<&str>) -> Option<PathBuf> {
        toolchain_candidates(kind_name(kind), language)
            .into_iter()
            .map(|c| self.toolchain_dir.join(c))
            .find(|p| p.exists())
    }
}

/// The ordered toolchain-image filenames to try for a target (most specific
/// first). Pure so it can be unit-tested without a full [`BuildDeps`].
fn toolchain_candidates(kind_name: &str, language: Option<&str>) -> Vec<String> {
    let mut candidates: Vec<String> = Vec::new();
    if let Some(lang) = language.filter(|l| !l.is_empty()) {
        candidates.push(format!("{lang}.ext4"));
    }
    candidates.push(format!("jkbuild-{kind_name}.ext4"));
    candidates.push(format!("{kind_name}.ext4"));
    candidates.push("default.ext4".to_string());
    candidates
}

/// Cheap host-side language sniff to pick the per-language BUILD IMAGE before the
/// VM boots. The authoritative detect runs in-VM (jkbuild); this only chooses
/// which toolchain image to boot, so it stays a shallow file check. An explicit
/// `hint` (from jkbase.toml `language=`) always wins.
pub fn detect_language(source_path: &Path, hint: Option<&str>) -> Option<String> {
    if let Some(h) = hint.filter(|h| !h.is_empty()) {
        return Some(h.to_string());
    }
    let has = |f: &str| source_path.join(f).exists();
    if has("bun.lockb") || has("bun.lock") || has("bunfig.toml") {
        return Some("bun".to_string());
    }
    if let Ok(pkg) = std::fs::read_to_string(source_path.join("package.json"))
        && pkg.contains("bun@")
    {
        return Some("bun".to_string());
    }
    None
}

/// Build the `build_callback` closure for `AppState` from shared deps. Mirrors
/// the server's `deploy_callback`: control owns the funnel, this owns the orch.
pub fn build_callback(deps: Arc<BuildDeps>) -> jkbase_control::api::BuildCallback {
    Arc::new(move |ctx: jkbase_control::api::BuildContext| {
        let deps = deps.clone();
        Box::pin(async move {
            run_project_build(ctx.project_id, ctx.build_id, ctx.source_tar_gz, deps).await
        })
    })
}

/// Boot-time reconciliation: nothing is in-flight at startup, so fail any build
/// record left Queued/Building by a previous crash/restart (otherwise it shows
/// "building" forever and the CLI poll loop never terminates), and reap orphaned
/// build workspaces + staging dirs that a crash left behind.
pub fn reconcile_on_boot(store: &jkbase_control::store::Store, data_dir: &Path, deploy_dir: &Path) {
    use jkbase_control::store::BuildRecord;
    if let Ok(projects) = store.list_projects() {
        for p in projects {
            if let Ok(builds) = store.list_builds(&p.id) {
                for b in builds {
                    if matches!(b.phase, BuildPhase::Queued | BuildPhase::Building) {
                        let failed = BuildRecord {
                            phase: BuildPhase::Failed,
                            error: Some("server restarted during build".to_string()),
                            updated_at: now(),
                            ..b
                        };
                        if let Err(e) = store.save_build(&failed) {
                            warn!(project = %p.id, build = failed.build_id, error = %e,
                                  "failed to fail stale build record on boot");
                        }
                    }
                }
            }
            // Reap this project's stale staging dirs (`.staging-deploy`/`.staging-build-*`).
            if let Ok(entries) = std::fs::read_dir(deploy_dir.join(&p.id)) {
                for e in entries.flatten() {
                    if e.file_name().to_string_lossy().starts_with(".staging") {
                        let _ = std::fs::remove_dir_all(e.path());
                    }
                }
            }
        }
    }
    // Nothing is in-flight at boot, so every build workspace is an orphan.
    let _ = std::fs::remove_dir_all(data_dir.join("builds"));
}

/// Stage the kernel onto the data-dir filesystem as a world-readable (0o444)
/// copy, so each build VM can hard-link it into its jail (same-fs requirement).
pub fn stage_kernel(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::copy(src, dst)
        .with_context(|| format!("stage build kernel {} -> {}", src.display(), dst.display()))?;
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(dst)?.permissions();
    perms.set_mode(0o444);
    std::fs::set_permissions(dst, perms)?;
    Ok(())
}

/// Best-effort provisioning of the parent build cgroup with pids/memory/cpu
/// controllers delegated — required for the jailer to apply per-build cgroup-v2
/// limits. Needs root (cgroup-v2 delegation); logs and continues on failure so a
/// non-root dev run still boots (builds just won't be runnable until provisioned,
/// reboot-surviving, by ops — a separate B0 card).
pub fn provision_cgroup(cgroup_mount: &Path, parent: &str) {
    let want = "+cpu +memory +pids";
    let root_sc = cgroup_mount.join("cgroup.subtree_control");
    if let Err(e) = std::fs::write(&root_sc, want) {
        warn!(error = %e, path = %root_sc.display(),
              "could not enable cgroup controllers at root; build VMs need root");
        return;
    }
    let parent_dir = cgroup_mount.join(parent);
    if let Err(e) = std::fs::create_dir_all(&parent_dir) {
        warn!(error = %e, path = %parent_dir.display(), "could not create build parent cgroup");
        return;
    }
    let parent_sc = parent_dir.join("cgroup.subtree_control");
    if let Err(e) = std::fs::write(&parent_sc, want) {
        warn!(error = %e, path = %parent_sc.display(),
              "could not delegate controllers to build parent cgroup");
        return;
    }
    info!(parent = %parent_dir.display(), "build cgroup provisioned");
}

/// Isolated per-build network: an IP/TAP slot pool on the build bridge. A build
/// VM can reach ONLY the egress proxy on the gateway (enforced host-side by the
/// firewall from `tools/setup-build-net.sh`); the proxy does the allowlist +
/// public-IP pinning. `None` in [`BuildDeps`] → offline (network-free) builds.
pub struct BuildNet {
    pub bridge: String,
    pub gateway: String,
    pub proxy_port: u16,
    subnet_prefix: String,
    uid: u32,
    free_slots: Mutex<Vec<u8>>,
}

/// A leased build-network slot (its TAP + guest IP/MAC); returned via [`BuildNet::release`].
pub struct NetLease {
    slot: u8,
    tap: String,
    guest_ip: String,
    mac: String,
}

impl BuildNet {
    /// `pool_size` concurrent slots → guest IPs `<subnet>.2 ..= .(1+pool_size)`.
    pub fn new(bridge: String, gateway: String, proxy_port: u16, uid: u32, pool_size: u8) -> Self {
        let subnet_prefix = {
            let mut parts: Vec<&str> = gateway.split('.').collect();
            parts.truncate(3);
            parts.join(".")
        };
        // Reversed so pop() hands out ascending slot numbers.
        let free_slots: Vec<u8> = (1..=pool_size).rev().collect();
        Self {
            bridge,
            gateway,
            proxy_port,
            subnet_prefix,
            uid,
            free_slots: Mutex::new(free_slots),
        }
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.gateway, self.proxy_port)
    }

    /// Lease a slot and bring up its TAP — owned by the build uid (so the jailed
    /// firecracker can open it) and mastered to the build bridge.
    pub async fn acquire(&self) -> Result<NetLease> {
        let slot = {
            let mut slots = self.free_slots.lock().await;
            slots
                .pop()
                .ok_or_else(|| anyhow::anyhow!("build network pool exhausted"))?
        };
        let tap = format!("jkbld{slot}");
        let guest_ip = format!("{}.{}", self.subnet_prefix, slot as u16 + 1);
        let mac = format!("AA:FC:00:1F:00:{slot:02X}");
        if let Err(e) = self.setup_tap(&tap).await {
            self.free_slots.lock().await.push(slot);
            return Err(e);
        }
        Ok(NetLease {
            slot,
            tap,
            guest_ip,
            mac,
        })
    }

    /// Tear the leased TAP down (idempotent — the seal may already have deleted
    /// it) and return its slot to the pool.
    pub async fn release(&self, lease: NetLease) {
        let _ = run_ip(&["link", "delete", &lease.tap]).await;
        self.free_slots.lock().await.push(lease.slot);
    }

    async fn setup_tap(&self, tap: &str) -> Result<()> {
        let _ = run_ip(&["link", "delete", tap]).await; // clear any stale device
        run_ip(&[
            "tuntap",
            "add",
            "dev",
            tap,
            "mode",
            "tap",
            "user",
            &self.uid.to_string(),
        ])
        .await?;
        run_ip(&["link", "set", tap, "master", &self.bridge]).await?;
        // Bridge port isolation: isolated ports cannot forward to each other at
        // L2 (only to the bridge/gateway), so concurrent tenants' build VMs are
        // mutually unreachable even though they share one bridge. This is what
        // actually blocks VM-to-VM lateral movement (the L3 FORWARD DROP never
        // sees intra-bridge frames).
        run_ip(&[
            "link", "set", "dev", tap, "type", "bridge_slave", "isolated", "on",
        ])
        .await?;
        // Belt-and-suspenders: drop IPv6 on the port (the guest also boots with
        // ipv6.disable=1), so there's no fe80:: path around the IPv4 firewall.
        let _ = tokio::process::Command::new("sysctl")
            .arg("-w")
            .arg(format!("net.ipv6.conf.{tap}.disable_ipv6=1"))
            .status()
            .await;
        run_ip(&["link", "set", tap, "up"]).await?;
        Ok(())
    }

    /// Verify the build bridge + firewall are provisioned (tools/setup-build-net.sh)
    /// before we ever launch a networked build VM — so attacker-controlled code is
    /// never run with the "reach only the proxy" isolation silently absent (e.g.
    /// after a reboot or an iptables flush). Errors listing what to run if not.
    pub async fn verify_firewall(&self) -> Result<()> {
        let bridge_up = tokio::process::Command::new("ip")
            .args(["link", "show", &self.bridge])
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !bridge_up {
            bail!(
                "build bridge {} missing — run `sudo tools/setup-build-net.sh`",
                self.bridge
            );
        }
        let input_hook = vec!["-C", "INPUT", "-i", self.bridge.as_str(), "-j", "JKBUILD"];
        let fwd_drop = vec!["-C", "FORWARD", "-i", self.bridge.as_str(), "-j", "DROP"];
        for check in [input_hook, fwd_drop] {
            let ok = tokio::process::Command::new("iptables")
                .args(&check)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                bail!(
                    "build firewall rule missing ({check:?}) — run `sudo tools/setup-build-net.sh`"
                );
            }
        }
        Ok(())
    }
}

/// Month-to-date build-seconds used vs the project's monthly cap, or `None` on a
/// store error (callers then proceed — fail-open mid-build is acceptable; the
/// intake 402 gate is the primary control).
fn build_quota_state(deps: &BuildDeps, project_id: &str) -> Option<(u64, u64)> {
    let month_start = jkbase_control::store::month_start_epoch(now());
    let used = deps
        .store
        .sum_month_to_date(project_id, month_start)
        .ok()?
        .build_seconds;
    let cap = deps.store.get_quota(project_id).ok()?.build_seconds_per_month;
    Some((used, cap))
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("ip").args(args).status().await?;
    if !status.success() {
        bail!("ip {args:?} failed: {status}");
    }
    Ok(())
}

/// The host seal action: delete the build VM's TAP so its COMPILE phase is
/// offline. Host-enforced — the guest can't recreate a host TAP.
fn make_seal(tap: String) -> SealFn {
    Box::new(move || {
        let tap = tap.clone();
        Box::pin(async move {
            let _ = tokio::process::Command::new("ip")
                .args(["link", "delete", &tap])
                .status()
                .await;
        })
    })
}

/// One unit of build work fanned out to its own build VM.
#[derive(Clone)]
struct TargetSpec {
    name: String,
    kind: TargetKind,
    /// Source subdir, relative to the unpacked source root.
    source_subdir: String,
    language: Option<String>,
}

/// Build-derived server manifest fields (the `cmd`/`env`/`working_dir` half of a
/// `ServerManifest`); jkbase.toml supplies the authoritative `port`/`health_check`
/// /`volumes` via [`jkbase_common::config::ServerConfig::manifest_value`].
#[derive(serde::Deserialize)]
struct BuiltServerManifest {
    #[serde(default)]
    cmd: Vec<String>,
    #[serde(default)]
    env: HashMap<String, String>,
    #[serde(default = "root_dir")]
    working_dir: String,
}

fn root_dir() -> String {
    "/".to_string()
}

impl Default for BuiltServerManifest {
    fn default() -> Self {
        Self {
            cmd: Vec::new(),
            env: HashMap::new(),
            working_dir: "/".to_string(),
        }
    }
}

/// The `build_callback` body: run one project build to a fully-assembled artifact
/// directory (or fail atomically). Always cleans its scratch workspace; on
/// failure also cleans the staged artifact dir so a failed build leaves no orphan.
pub async fn run_project_build(
    project_id: String,
    build_id: u64,
    source_tar_gz: Vec<u8>,
    deps: Arc<BuildDeps>,
) -> Result<PathBuf> {
    let workspace = deps
        .data_dir
        .join("builds")
        .join(&project_id)
        .join(build_id.to_string());
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace)
        .with_context(|| format!("create build workspace {}", workspace.display()))?;

    let result = run_inner(&project_id, build_id, &source_tar_gz, &deps, &workspace).await;

    // The workspace only holds throwaway source/output images — always reclaim it.
    let _ = std::fs::remove_dir_all(&workspace);
    result
}

async fn run_inner(
    project_id: &str,
    build_id: u64,
    source_tar_gz: &[u8],
    deps: &Arc<BuildDeps>,
    workspace: &Path,
) -> Result<PathBuf> {
    // 1. Unpack the source tree.
    let src_dir = workspace.join("src");
    std::fs::create_dir_all(&src_dir)?;
    unpack_tar_gz(source_tar_gz, &src_dir).context("unpack uploaded source tarball")?;

    // 2. Parse the manifest from the uploaded source, then reject any
    //    attacker-controlled name/path that could escape the build/deploy tree.
    let config = ProjectConfig::load(&src_dir.join("jkbase.toml"))
        .context("load jkbase.toml from uploaded source")?;
    validate_manifest(&config).context("reject unsafe names/paths in jkbase.toml")?;
    let config = Arc::new(config);

    // 3. Staged artifact dir, on the same filesystem as deploy_dir so the
    //    activate step can rename it into deployments/v{N}.
    let staged = deps
        .deploy_dir
        .join(project_id)
        .join(format!(".staging-build-{build_id}"));
    let _ = std::fs::remove_dir_all(&staged);
    std::fs::create_dir_all(&staged)?;

    let assemble_and_build = async {
        // 4. Non-build artifacts: sidecars + static site content.
        assemble_sidecars(&config, &staged).context("assemble config sidecars")?;
        assemble_sites(&config, &src_dir, &staged).context("assemble site content")?;
        std::fs::create_dir_all(staged.join("_functions"))?;
        std::fs::create_dir_all(staged.join("_servers"))?;

        // 5. Enumerate per-target build work.
        let specs = enumerate_targets(&config);
        if specs.is_empty() {
            info!(project_id, build_id, "no build targets; static/site-only deploy");
            return Ok(());
        }
        seed_targets(&deps.store, project_id, build_id, &specs);

        // 6. Fan out one build VM per target, bounded by a semaphore. Collect
        //    every result; any failure fails the whole build (atomic).
        let sem = Arc::new(Semaphore::new(deps.max_concurrent.max(1)));
        let record_lock = Arc::new(Mutex::new(()));
        let mut set = tokio::task::JoinSet::new();
        for spec in specs {
            let deps = deps.clone();
            let config = config.clone();
            let sem = sem.clone();
            let record_lock = record_lock.clone();
            let staged = staged.clone();
            let src_dir = src_dir.clone();
            let workspace = workspace.to_path_buf();
            let project_id = project_id.to_string();
            set.spawn(async move {
                let _permit = sem.acquire_owned().await.expect("build semaphore closed");
                let r = build_one_target(
                    &spec, &config, &deps, &src_dir, &workspace, &staged, &project_id, build_id,
                    &record_lock,
                )
                .await;
                (spec.name.clone(), r)
            });
        }

        let mut failures: Vec<String> = Vec::new();
        while let Some(joined) = set.join_next().await {
            match joined {
                Ok((name, Ok(()))) => info!(project_id, build_id, target = %name, "target built"),
                Ok((name, Err(e))) => failures.push(format!("{name}: {e:#}")),
                Err(join_err) => failures.push(format!("build task panicked: {join_err}")),
            }
        }
        if !failures.is_empty() {
            bail!(
                "{} build target(s) failed: {}",
                failures.len(),
                failures.join("; ")
            );
        }
        Ok(())
    };

    match assemble_and_build.await {
        Ok(()) => Ok(staged),
        Err(e) => {
            let _ = std::fs::remove_dir_all(&staged);
            Err(e)
        }
    }
}

#[allow(clippy::too_many_arguments)] // shared build context threaded into one VM
async fn build_one_target(
    spec: &TargetSpec,
    config: &ProjectConfig,
    deps: &BuildDeps,
    src_dir: &Path,
    workspace: &Path,
    staged: &Path,
    project_id: &str,
    build_id: u64,
    record_lock: &Mutex<()>,
) -> Result<()> {
    update_target(
        deps,
        record_lock,
        project_id,
        build_id,
        &spec.name,
        BuildPhase::Building,
        |t| t.started_at = Some(now()),
        None,
    )
    .await;

    let outcome = build_one_target_inner(
        spec, config, deps, src_dir, workspace, staged, project_id, build_id,
    )
    .await;

    match &outcome {
        Ok(log) => {
            update_target(
                deps,
                record_lock,
                project_id,
                build_id,
                &spec.name,
                BuildPhase::Succeeded,
                |t| t.finished_at = Some(now()),
                log.as_deref(),
            )
            .await;
        }
        Err(e) => {
            let detail = format!("{e:#}");
            update_target(
                deps,
                record_lock,
                project_id,
                build_id,
                &spec.name,
                BuildPhase::Failed,
                |t| {
                    t.finished_at = Some(now());
                    t.detail = Some(detail.clone());
                },
                None,
            )
            .await;
        }
    }
    outcome.map(|_| ())
}

/// Build one target in its own jailed VM and place its artifact into `staged`.
/// Returns the captured build-log tail on success (for the build record).
#[allow(clippy::too_many_arguments)] // shared build context threaded into one VM
async fn build_one_target_inner(
    spec: &TargetSpec,
    config: &ProjectConfig,
    deps: &BuildDeps,
    src_dir: &Path,
    workspace: &Path,
    staged: &Path,
    project_id: &str,
    build_id: u64,
) -> Result<Option<Vec<u8>>> {
    // Mid-fan-out quota circuit breaker: the pre-build 402 gate checks only at
    // intake, but a build fans out one metered VM per target — refuse remaining
    // targets once month-to-date build-seconds reach the cap, so a many-target
    // manifest can't overrun the cap by the target count (threat-model P1-4).
    if let Some((used, cap)) = build_quota_state(deps, project_id)
        && used >= cap
    {
        bail!("build-minute quota exhausted ({used}/{cap} build-seconds this month)");
    }

    let source_path = src_dir.join(&spec.source_subdir);
    if !source_path.is_dir() {
        bail!(
            "source dir '{}' not found for target '{}'",
            spec.source_subdir,
            spec.name
        );
    }
    // Resolve the language: the explicit jkbase.toml hint, else a cheap host-side
    // sniff of the source (the in-VM lifecycle does the authoritative detect).
    let language = detect_language(&source_path, spec.language.as_deref());
    let toolchain = deps
        .select_toolchain(spec.kind, language.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no toolchain image for {}{} in {}",
                kind_name(spec.kind),
                language
                    .as_deref()
                    .map(|l| format!("/{l}"))
                    .unwrap_or_default(),
                deps.toolchain_dir.display()
            )
        })?;

    let tag = format!("{}-{}", kind_name(spec.kind), sanitize(&spec.name));
    let source_img = workspace.join(format!("{tag}.source.img"));
    let output_img = workspace.join(format!("{tag}.output.img"));

    // RO source drive built from the subdir in userspace — no mount (P0-3).
    build_ro_ext4_from_dir(&source_path, &source_img, 16)
        .with_context(|| format!("build source image for '{}'", spec.name))?;

    // Keep the VM id short: it becomes the jailer chroot path, and the Firecracker
    // API Unix socket under it must stay within SUN_LEN (~108 bytes). Checked
    // BEFORE leasing a TAP, so a too-long path bails without leaking a net slot.
    let kind_char = match spec.kind {
        TargetKind::Function => 'f',
        TargetKind::Server => 's',
    };
    let short_name: String = sanitize(&spec.name).chars().take(16).collect();
    let vm_id = format!("b{build_id}-{kind_char}-{short_name}");
    let exec_basename = deps
        .firecracker_bin
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("firecracker");
    let socket_len = deps.chroot_base.as_os_str().len()
        + 1
        + exec_basename.len()
        + 1
        + vm_id.len()
        + "/root/run/firecracker.socket".len();
    if socket_len >= 108 {
        bail!(
            "build VM socket path would be {socket_len} bytes (>= SUN_LEN 108); \
             shorten the data dir or the target name"
        );
    }

    // Lease an isolated TAP when a build network is configured, so this VM can
    // fetch deps through the egress proxy during FETCH and is sealed for COMPILE.
    let lease = match &deps.net {
        Some(net) => Some(net.acquire().await.context("acquire build network")?),
        None => None,
    };
    let (tap_device, guest_mac, guest_ip, gateway_ip, egress_proxy, seal) =
        match (&deps.net, &lease) {
            (Some(net), Some(l)) => (
                Some(l.tap.clone()),
                Some(l.mac.clone()),
                Some(l.guest_ip.clone()),
                Some(net.gateway.clone()),
                Some(net.proxy_url()),
                Some(make_seal(l.tap.clone())),
            ),
            _ => (None, None, None, None, None, None),
        };

    let cfg = BuildVmConfig {
        jailer_bin: deps.jailer_bin.clone(),
        firecracker_bin: deps.firecracker_bin.clone(),
        kernel_path: deps.kernel_path.clone(),
        toolchain_rootfs: toolchain,
        source_drive: source_img.clone(),
        scratch_size_bytes: deps.scratch_size_bytes,
        output_drive: output_img.clone(),
        output_size_bytes: deps.output_size_bytes,
        cache_drive: None,
        vcpu_count: deps.vcpu_count,
        mem_size_mib: deps.mem_size_mib,
        vsock_cid: None,
        timeout: deps.timeout,
        chroot_base: deps.chroot_base.clone(),
        cgroup_mount: deps.cgroup_mount.clone(),
        uid: deps.uid,
        gid: deps.gid,
        parent_cgroup: deps.parent_cgroup.clone(),
        cgroup_pids_max: deps.cgroup_pids_max,
        cgroup_mem_max_bytes: deps.cgroup_mem_max_bytes,
        cgroup_cpu_max: deps.cgroup_cpu_max.clone(),
        // RLIMIT_FSIZE is process-wide on Firecracker, so it must cover the
        // LARGEST RW backing file it writes — the scratch drive, not just output
        // (a 64 MiB cap with a 256 MiB scratch SIGXFSZ-kills any real build that
        // writes past 64 MiB of scratch). The artifact size is already bounded by
        // the fixed output-drive size. NB: include the cache image when wired.
        fsize_limit_bytes: Some(deps.scratch_size_bytes.max(deps.output_size_bytes)),
        console_log_max_bytes: deps.console_log_max_bytes,
        seccomp_filter: None,
        netns: None,
        tap_device,
        guest_mac,
        guest_ip,
        gateway_ip,
        egress_proxy,
        lang_hint: language.clone(),
        fetch_deadline: deps.fetch_deadline,
        seal,
    };

    let runtime_dir = workspace.join("run");
    let run_res = BuildVm::run(&vm_id, &cfg, &runtime_dir).await;
    // Always return the network lease (delete TAP + free slot), even on error.
    if let (Some(net), Some(l)) = (&deps.net, lease) {
        net.release(l).await;
    }
    let run = run_res.with_context(|| format!("run build VM for '{}'", spec.name))?;

    // Meter on exit BEFORE any outcome bail — even timed-out/crashed builds held
    // resources (anti-mining, threat-model P1-4). build_seconds = max(cgroup CPU,
    // wall-clock floor), so a sub-tick build can't escape billing.
    let cpu_secs = run.cpu_usec.map(|u| u.div_ceil(1_000_000)).unwrap_or(0);
    let build_secs = cpu_secs.max(run.wall.as_secs());
    if build_secs > 0 {
        let hour = (now() / 3600) * 3600;
        if let Err(e) = deps.store.add_build_usage(project_id, hour, build_secs) {
            warn!(project = %project_id, target = %spec.name, error = %e,
                  "failed to record build-minute usage");
        }
    }
    let outcome = run.outcome;

    // Best-effort: the log tail is useful even when the build failed.
    let log_tail = build_output::read_capped(&output_img, "/build.log", TARGET_LOG_CAP)
        .ok()
        .flatten();
    let log_str = || {
        log_tail
            .as_deref()
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };

    match outcome {
        BuildOutcome::Completed => {}
        BuildOutcome::TimedOut => {
            bail!("build timed out after {}s\n{}", deps.timeout.as_secs(), log_str())
        }
        BuildOutcome::Crashed { code, signal } => bail!(
            "build VM crashed (code={code:?}, signal={signal:?}) — likely cgroup OOM-kill or panic\n{}",
            log_str()
        ),
    }

    let status = build_output::read_status(&output_img)?;
    if status != Some(0) {
        bail!("build script exited with status {status:?}\n{}", log_str());
    }

    match spec.kind {
        TargetKind::Function => {
            let dest = staged.join("_functions").join(format!("{}.wasm", spec.name));
            if !build_output::dump_file(&output_img, "/function.wasm", &dest)? {
                bail!("function build produced no /function.wasm artifact");
            }
        }
        TargetKind::Server => {
            let rootfs_dest = staged.join("_servers").join(format!("{}.tar.gz", spec.name));
            if !build_output::dump_file(&output_img, "/rootfs.tar.gz", &rootfs_dest)? {
                bail!("server build produced no /rootfs.tar.gz artifact");
            }
            let built = read_built_manifest(&output_img, workspace, &tag)?;
            let server_cfg = config
                .servers
                .get(&spec.name)
                .ok_or_else(|| anyhow::anyhow!("server '{}' missing from config", spec.name))?;
            let manifest =
                server_cfg.manifest_value(built.cmd, built.env, &built.working_dir);
            let json = serde_json::to_string_pretty(&manifest)?;
            std::fs::write(staged.join("_servers").join(format!("{}.json", spec.name)), json)?;
        }
    }

    Ok(log_tail)
}

/// Read the build-derived `/manifest.json` (server targets), or defaults if absent.
fn read_built_manifest(output_img: &Path, workspace: &Path, tag: &str) -> Result<BuiltServerManifest> {
    let tmp = workspace.join(format!("{tag}.manifest.json"));
    if build_output::dump_file(output_img, "/manifest.json", &tmp)? {
        let bytes = std::fs::read(&tmp)?;
        let _ = std::fs::remove_file(&tmp);
        Ok(serde_json::from_slice(&bytes).unwrap_or_default())
    } else {
        Ok(BuiltServerManifest::default())
    }
}

/// Reject manifest-supplied names and paths that could escape the build/deploy
/// tree. The uploaded `jkbase.toml` is fully attacker-controlled (all tenants
/// untrusted): target/site NAMES become filesystem dest paths
/// (`_functions/{name}.wasm`, `_servers/{name}.tar.gz`, `_site_{name}/`), and
/// source/public PATHS are joined onto the unpacked source root. A `..`, an
/// absolute path, or a `/`-bearing name would let a tenant read arbitrary
/// host files into the build VM or write artifacts into another tenant's tree.
/// Max build targets (functions + servers) per build — bounds the fan-out so a
/// hostile manifest can't launch an unbounded number of metered build VMs.
const MAX_TARGETS: usize = 64;

fn validate_manifest(config: &ProjectConfig) -> Result<()> {
    let target_count = config.functions.len() + config.servers.len();
    if target_count > MAX_TARGETS {
        bail!("too many build targets ({target_count}); max {MAX_TARGETS} functions + servers");
    }

    fn name_ok(n: &str) -> bool {
        !n.is_empty()
            && n.len() <= 64
            && n.chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    }
    // A relative path with no `..`, no root, no Windows prefix — confined to root.
    fn path_ok(p: &str) -> bool {
        let path = Path::new(p);
        !path.is_absolute()
            && !path.components().any(|c| {
                matches!(
                    c,
                    std::path::Component::ParentDir
                        | std::path::Component::RootDir
                        | std::path::Component::Prefix(_)
                )
            })
    }

    for (kind, name) in config
        .functions
        .keys()
        .map(|n| ("function", n))
        .chain(config.servers.keys().map(|n| ("server", n)))
        .chain(config.sites.keys().map(|n| ("site", n)))
    {
        if !name_ok(name) {
            bail!("invalid {kind} name {name:?}: must be 1-64 chars of [A-Za-z0-9_-]");
        }
    }
    for (name, f) in &config.functions {
        if !path_ok(&f.source) {
            bail!("function '{name}' source {:?} must be a relative path inside the project (no '..' or absolute)", f.source);
        }
    }
    for (name, s) in &config.servers {
        let sd = s.source_dir();
        if !path_ok(sd) {
            bail!("server '{name}' source {sd:?} must be a relative path inside the project (no '..' or absolute)");
        }
    }
    for (name, site) in &config.sites {
        if !path_ok(&site.public) {
            bail!("site '{name}' public {:?} must be a relative path inside the project (no '..' or absolute)", site.public);
        }
    }
    if let Some(public) = config.hosting.as_ref().and_then(|h| h.public.as_deref())
        && !path_ok(public)
    {
        bail!("hosting public {public:?} must be a relative path inside the project (no '..' or absolute)");
    }
    Ok(())
}

fn enumerate_targets(config: &ProjectConfig) -> Vec<TargetSpec> {
    let mut specs: Vec<TargetSpec> = Vec::new();
    for (name, f) in &config.functions {
        specs.push(TargetSpec {
            name: name.clone(),
            kind: TargetKind::Function,
            source_subdir: f.source.clone(),
            language: f.language.clone(),
        });
    }
    for (name, s) in &config.servers {
        specs.push(TargetSpec {
            name: name.clone(),
            kind: TargetKind::Server,
            source_subdir: s.source_dir().to_string(),
            language: s.language.clone(),
        });
    }
    // Deterministic order regardless of HashMap iteration.
    specs.sort_by(|a, b| (kind_name(a.kind), &a.name).cmp(&(kind_name(b.kind), &b.name)));
    specs
}

fn assemble_sidecars(config: &ProjectConfig, staged: &Path) -> Result<()> {
    if let Some(j) = config.routes_json() {
        std::fs::write(staged.join("_routes.json"), j)?;
    }
    if let Some(j) = config.sites_json() {
        std::fs::write(staged.join("_sites.json"), j)?;
    }
    if let Some(j) = config.domains_json() {
        std::fs::write(staged.join("_domains.json"), j)?;
    }
    if let Some(j) = config.schedules_json() {
        std::fs::write(staged.join("_schedules.json"), j)?;
    }
    Ok(())
}

fn assemble_sites(config: &ProjectConfig, src_dir: &Path, staged: &Path) -> Result<()> {
    let sites = config.resolved_sites();
    if config.is_multi_site() {
        for site in &sites {
            let site_dir = src_dir.join(&site.public);
            if site_dir.is_dir() {
                copy_filtered(&site_dir, &staged.join(format!("_site_{}", site.name)))?;
            }
        }
    } else if let Some(site) = sites.first() {
        let site_dir = src_dir.join(&site.public);
        if site_dir.is_dir() {
            copy_filtered(&site_dir, staged)?;
        }
    }
    Ok(())
}

/// Recursively copy `src` into `dst`, skipping the build/VCS dirs and manifest
/// files (mirrors the CLI's old packaging exclusions). Symlinks are skipped.
fn copy_filtered(src: &Path, dst: &Path) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        } else if ft.is_dir() {
            if EXCLUDED_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            copy_filtered(&entry.path(), &dst.join(&name))?;
        } else if ft.is_file() {
            if EXCLUDED_FILES.contains(&name_str.as_ref()) {
                continue;
            }
            std::fs::copy(entry.path(), dst.join(&name))?;
        }
    }
    Ok(())
}

fn unpack_tar_gz(bytes: &[u8], dest: &Path) -> Result<()> {
    // tar-rs `unpack` refuses entries that escape `dest` (no `..`/absolute
    // traversal). The hostile-code boundary is the build VM, not this untar.
    let gz = flate2::read::GzDecoder::new(bytes);
    let mut archive = tar::Archive::new(gz);
    archive.unpack(dest)?;
    Ok(())
}

// -- build-record progress (persisted to the same redb the API reads) --

fn seed_targets(store: &Store, project_id: &str, build_id: u64, specs: &[TargetSpec]) {
    if let Ok(Some(mut r)) = store.get_build(project_id, build_id) {
        r.targets = specs
            .iter()
            .map(|s| BuildTargetStatus {
                name: s.name.clone(),
                kind: s.kind,
                phase: BuildPhase::Queued,
                detail: None,
                cache_hit: false,
                started_at: None,
                finished_at: None,
                builder_digest: None,
                cache_key: None,
                source_commit: None,
                duration_breakdown_ms: Default::default(),
            })
            .collect();
        r.updated_at = now();
        if let Err(e) = store.save_build(&r) {
            warn!(project_id, build_id, error = %e, "failed to seed build targets");
        }
    }
}

#[allow(clippy::too_many_arguments)] // one record mutation: identity + change + log
async fn update_target(
    deps: &BuildDeps,
    record_lock: &Mutex<()>,
    project_id: &str,
    build_id: u64,
    name: &str,
    phase: BuildPhase,
    mutate: impl FnOnce(&mut BuildTargetStatus),
    append_log: Option<&[u8]>,
) {
    let _g = record_lock.lock().await;
    if let Ok(Some(mut r)) = deps.store.get_build(project_id, build_id) {
        if let Some(t) = r.targets.iter_mut().find(|t| t.name == name) {
            t.phase = phase;
            mutate(t);
        }
        if let Some(log) = append_log {
            append_log_tail(&mut r.log_tail, name, log);
        }
        r.updated_at = now();
        if let Err(e) = deps.store.save_build(&r) {
            warn!(project_id, build_id, target = %name, error = %e, "failed to persist build progress");
        }
    }
}

/// Append a target's log slice to the combined tail, keeping the last
/// [`LOG_TAIL_CAP`] bytes so a chatty build can't grow the record unbounded.
fn append_log_tail(tail: &mut String, name: &str, log: &[u8]) {
    if log.is_empty() {
        return;
    }
    tail.push_str(&format!("\n===== {name} =====\n"));
    tail.push_str(&String::from_utf8_lossy(log));
    if tail.len() > LOG_TAIL_CAP {
        // Keep the tail; trim on a char boundary.
        let cut = tail.len() - LOG_TAIL_CAP;
        let mut idx = cut;
        while idx < tail.len() && !tail.is_char_boundary(idx) {
            idx += 1;
        }
        *tail = tail.split_off(idx);
    }
}

fn kind_name(kind: TargetKind) -> &'static str {
    match kind {
        TargetKind::Function => "function",
        TargetKind::Server => "server",
    }
}

/// Sanitize a name into `[a-z0-9-]` for use in VM ids and file tags.
fn sanitize(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() {
                c.to_ascii_lowercase()
            } else {
                '-'
            }
        })
        .collect::<String>()
        .trim_matches('-')
        .to_string()
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn enumerate_and_assemble_are_deterministic() {
        let cfg: ProjectConfig = toml::from_str(
            r#"
            [functions.zeta]
            source = "./fns/zeta"
            [functions.alpha]
            source = "./fns/alpha"
            language = "rust"
            [servers.web]
            source = "./server"
            port = 8080
            [sites.docs]
            public = "./docs"
            "#,
        )
        .unwrap();

        let specs = enumerate_targets(&cfg);
        // functions sort before servers (kind name), then by name.
        let order: Vec<_> = specs.iter().map(|s| s.name.as_str()).collect();
        assert_eq!(order, vec!["alpha", "zeta", "web"]);
        assert_eq!(specs[0].language.as_deref(), Some("rust"));
        assert_eq!(specs[2].kind, TargetKind::Server);
        assert_eq!(specs[2].source_subdir, "./server");
    }

    #[test]
    fn sidecars_written_only_when_present() {
        let dir = std::env::temp_dir().join(format!("jkb-asm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: ProjectConfig = toml::from_str(
            "[routes.\"a.example.com\"]\nservice = \"function\"\nname = \"api\"\n",
        )
        .unwrap();
        assemble_sidecars(&cfg, &dir).unwrap();
        assert!(dir.join("_routes.json").exists());
        assert!(!dir.join("_sites.json").exists());
        assert!(!dir.join("_schedules.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn log_tail_caps_at_limit() {
        let mut tail = String::new();
        append_log_tail(&mut tail, "x", &vec![b'a'; LOG_TAIL_CAP * 2]);
        assert!(tail.len() <= LOG_TAIL_CAP);
    }

    #[test]
    fn sanitize_strips_specials() {
        assert_eq!(sanitize("My_Func.01"), "my-func-01");
        assert_eq!(sanitize("--a--"), "a");
    }

    #[test]
    fn toolchain_candidates_prefer_language_then_jkbuild_then_default() {
        assert_eq!(
            toolchain_candidates("server", Some("bun")),
            ["bun.ext4", "jkbuild-server.ext4", "server.ext4", "default.ext4"]
                .map(String::from)
                .to_vec()
        );
        assert_eq!(
            toolchain_candidates("server", None),
            ["jkbuild-server.ext4", "server.ext4", "default.ext4"]
                .map(String::from)
                .to_vec()
        );
        // An empty language string is ignored (no `.ext4` candidate).
        assert_eq!(
            toolchain_candidates("function", Some("")),
            ["jkbuild-function.ext4", "function.ext4", "default.ext4"]
                .map(String::from)
                .to_vec()
        );
    }

    #[test]
    fn detect_language_sniffs_bun_and_honours_hint() {
        let dir = std::env::temp_dir().join(format!("jkb-detect-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        // An explicit hint always wins; an empty hint is ignored.
        assert_eq!(detect_language(&dir, Some("rust")).as_deref(), Some("rust"));
        assert_eq!(detect_language(&dir, Some("")), None);
        // Bare dir → no detection.
        assert_eq!(detect_language(&dir, None), None);

        std::fs::write(dir.join("bun.lock"), "").unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("bun"));
        std::fs::remove_file(dir.join("bun.lock")).unwrap();

        // package.json declaring bun as the package manager also counts.
        std::fs::write(dir.join("package.json"), r#"{"packageManager":"bun@1.1.34"}"#).unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("bun"));

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn validate_manifest_rejects_traversal_and_bad_names() {
        // Clean manifest passes.
        let ok: ProjectConfig = toml::from_str(
            "[functions.api]\nsource = \"./functions/api\"\n[servers.web]\nsource = \"server\"\nport = 80\n[sites.docs]\npublic = \"./public\"\n",
        )
        .unwrap();
        assert!(validate_manifest(&ok).is_ok());

        // Absolute source path → reject (would package host files into the VM).
        let abs: ProjectConfig =
            toml::from_str("[functions.api]\nsource = \"/etc\"\n").unwrap();
        assert!(validate_manifest(&abs).is_err());

        // Parent-dir traversal in a source path → reject.
        let dotdot: ProjectConfig =
            toml::from_str("[functions.api]\nsource = \"../../etc\"\n").unwrap();
        assert!(validate_manifest(&dotdot).is_err());

        // Traversal in a SERVER source dir → reject.
        let srv: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"../secrets\"\nport = 80\n").unwrap();
        assert!(validate_manifest(&srv).is_err());

        // Traversal in a site public path → reject.
        let site: ProjectConfig =
            toml::from_str("[sites.docs]\npublic = \"../../root\"\n").unwrap();
        assert!(validate_manifest(&site).is_err());

        // Name with a path separator → reject (would escape the staged dest).
        let badname: ProjectConfig = toml::from_str(
            "[functions.\"../../evil\"]\nsource = \"./x\"\n",
        )
        .unwrap();
        assert!(validate_manifest(&badname).is_err());

        // hosting.public traversal → reject.
        let host: ProjectConfig =
            toml::from_str("[hosting]\npublic = \"../..\"\n").unwrap();
        assert!(validate_manifest(&host).is_err());
    }
}

/// On-box validation of the *real* `run_project_build` fan-out (2 functions +
/// 1 server + a site) on live KVM. Ignored by default — needs root (jailer), a
/// baked toolchain, and the parent build cgroup provisioned. Build unprivileged
/// then run the test binary under sudo (mirrors the `build_vm_smoke` example):
///
///   cargo test -p jkbase-server --no-run
///   sudo env JKB_DATA=/tmp/jkbob JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
///       <test-bin> --ignored --nocapture full_fanout_builds_all_targets
///
/// Expects `$JKB_DATA/vmlinux.bin` and `$JKB_DATA/toolchains/default.ext4`
/// (same filesystem as `$JKB_DATA`), and the cgroup provisioned by the harness.
#[cfg(test)]
mod onbox {
    use super::*;
    use jkbase_control::store::{BuildPhase, BuildRecord, Store};

    const FN_BUILD: &str = "#!/bin/sh\nprintf '\\000asm\\001\\000\\000\\000' > \"$OUT/function.wasm\"\necho ok\n";
    const SERVER_BUILD: &str = "#!/bin/sh\nmkdir -p /tmp/rf/srv\necho hi > /tmp/rf/srv/index.html\ntar -czf \"$OUT/rootfs.tar.gz\" -C /tmp/rf .\nprintf '{\"cmd\":[\"/srv/app\"],\"working_dir\":\"/srv\",\"env\":{\"K\":\"V\"}}' > \"$OUT/manifest.json\"\n";

    fn write(p: std::path::PathBuf, c: &str) {
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, c).unwrap();
    }

    #[tokio::test]
    #[ignore = "needs KVM + root + baked toolchain; set JKB_DATA + JKB_FC_RELEASE"]
    async fn full_fanout_builds_all_targets() {
        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return;
        };

        // Fixture source: 2 functions (one scheduled) + 1 server + a named site.
        let src = data.join("fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write(
            src.join("jkbase.toml"),
            r#"
[project]
name = "fixture"
[functions.api]
source = "./functions/api"
[functions.cron]
source = "./functions/cron"
schedule = "*/5 * * * *"
[servers.web]
source = "./server"
port = 8080
[servers.web.health_check]
path = "/healthz"
[sites.docs]
public = "./public"
"#,
        );
        write(src.join("functions/api/build.sh"), FN_BUILD);
        write(src.join("functions/cron/build.sh"), FN_BUILD);
        write(src.join("server/build.sh"), SERVER_BUILD);
        write(src.join("public/index.html"), "<h1>docs</h1>");

        let mut tarbuf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarbuf, flate2::Compression::fast());
            let mut tb = tar::Builder::new(enc);
            tb.append_dir_all(".", &src).unwrap();
            tb.into_inner().unwrap().finish().unwrap();
        }

        let store = Store::open(&data.join("onbox-test.redb")).unwrap();
        let (project_id, build_id) = ("fixture", 1u64);
        store
            .save_build(&BuildRecord {
                project_id: project_id.into(),
                build_id,
                phase: BuildPhase::Building,
                targets: vec![],
                log_tail: String::new(),
                phase_timings_ms: Default::default(),
                deployed_version: None,
                error: None,
                source_commit: None,
                created_at: now(),
                updated_at: now(),
            })
            .unwrap();

        let deps = Arc::new(BuildDeps {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: data.join("vmlinux.bin"),
            data_dir: data.clone(),
            deploy_dir: data.join("hosting"),
            toolchain_dir: data.join("toolchains"),
            store: store.clone(),
            chroot_base: data.join("bj"),
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            parent_cgroup: "jkbase-build".into(),
            uid: 100_000,
            gid: 100_000,
            timeout: Duration::from_secs(60),
            vcpu_count: 1,
            mem_size_mib: 512,
            cgroup_pids_max: 512,
            cgroup_mem_max_bytes: 512 * 1024 * 1024,
            cgroup_cpu_max: "100000 100000".into(),
            scratch_size_bytes: 256 * 1024 * 1024,
            output_size_bytes: 64 * 1024 * 1024,
            console_log_max_bytes: 1024 * 1024,
            max_concurrent: 2,
            net: None,
            fetch_deadline: Duration::from_secs(60),
        });
        std::fs::create_dir_all(&deps.chroot_base).unwrap();

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone())
            .await
            .expect("fan-out build should succeed");

        // Per-target artifacts assembled into the deploy shape.
        assert!(staged.join("_functions/api.wasm").exists(), "api.wasm");
        assert!(staged.join("_functions/cron.wasm").exists(), "cron.wasm");
        assert!(staged.join("_servers/web.tar.gz").exists(), "web rootfs");

        // Server manifest = build-derived cmd/env/working_dir + jkbase.toml port/health.
        let mani: serde_json::Value =
            serde_json::from_slice(&std::fs::read(staged.join("_servers/web.json")).unwrap())
                .unwrap();
        assert_eq!(mani["port"], 8080);
        assert_eq!(mani["cmd"][0], "/srv/app");
        assert_eq!(mani["working_dir"], "/srv");
        assert_eq!(mani["env"]["K"], "V");
        assert_eq!(mani["health_check"]["path"], "/healthz");

        // Sidecars + site content.
        assert!(staged.join("_sites.json").exists(), "_sites.json");
        assert!(staged.join("_schedules.json").exists(), "_schedules.json");
        assert!(staged.join("_site_docs/index.html").exists(), "site content");

        // Per-target progress recorded for GET /builds/{id}.
        let rec = store.get_build(project_id, build_id).unwrap().unwrap();
        assert_eq!(rec.targets.len(), 3);
        assert!(rec.targets.iter().all(|t| t.phase == BuildPhase::Succeeded));

        // Build minutes metered on exit (3 VMs, each ≥1 wall-clock second).
        let month_start = jkbase_control::store::month_start_epoch(now());
        let billed = store
            .sum_month_to_date(project_id, month_start)
            .unwrap()
            .build_seconds;
        assert!(billed >= 3, "expected ≥3 build-seconds, got {billed}");

        let _ = std::fs::remove_dir_all(&staged);
        println!("PASS: real run_project_build fan-out — 2 fn + 1 server + sidecars + manifest");
    }

    /// On-box: a real networked build VM reaches the network ONLY through the
    /// egress proxy (allowlist enforced), cannot egress directly (firewall), and
    /// is sealed for compile. Ignored by default — needs KVM + root + outbound
    /// internet AND the build bridge/firewall provisioned (tools/setup-build-net.sh).
    /// Run with `--ignored` after `sudo tools/setup-build-net.sh`.
    #[tokio::test]
    #[ignore = "needs KVM + root + internet + provisioned build bridge"]
    async fn networked_build_egress_allowlist_and_seal() {
        use jkbase_orch::build_output;
        use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};

        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return;
        };

        // Egress proxy on the build gateway (firewall lets build VMs reach it).
        let listener = tokio::net::TcpListener::bind("172.31.0.1:3128").await.unwrap();
        tokio::spawn(crate::egress::serve(
            listener,
            Arc::new(crate::egress::EgressConfig::with_default_allowlist()),
        ));

        // Fixture: build.sh probes the proxy (allow + block), direct egress
        // (firewall must block it), and the seal (compile must be offline).
        let src = data.join("net-src");
        let _ = std::fs::remove_dir_all(&src);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::write(
            src.join("build.sh"),
            r#"#!/bin/sh
P=172.31.0.1; PP=3128
status() { printf "CONNECT %s:443 HTTP/1.1\r\nHost: %s\r\n\r\n" "$1" "$1" | nc -w 5 $P $PP 2>/dev/null | head -1 | grep -oE '[0-9]{3}' | head -1; }
case "${1:-all}" in
  fetch)
    status registry.npmjs.org > /out/allow
    status evil.example.com   > /out/block
    if nc -w 4 1.1.1.1 443 </dev/null >/dev/null 2>&1; then echo up; else echo down; fi > /out/direct
    ;;
  compile)
    if nc -w 4 $P $PP </dev/null >/dev/null 2>&1; then echo up; else echo down; fi > /out/sealed
    cp "$SRC/app.wasm" "$OUT/function.wasm"
    ;;
esac
"#,
        )
        .unwrap();
        std::fs::write(src.join("app.wasm"), b"\0asm\x01\0\0\0net").unwrap();

        let workspace = data.join("net-ws");
        let _ = std::fs::remove_dir_all(&workspace);
        std::fs::create_dir_all(&workspace).unwrap();
        let source_img = workspace.join("source.img");
        let output_img = workspace.join("output.img");
        build_ro_ext4_from_dir(&src, &source_img, 16).unwrap();

        let net = BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, 100_000, 8);
        let lease = net.acquire().await.expect("acquire build net");
        let release = format!("/sys/class/net/{}", lease.tap); // for diagnostics only
        eprintln!("leased tap={} ip={} ({release})", lease.tap, lease.guest_ip);

        let cfg = BuildVmConfig {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: data.join("vmlinux.bin"),
            toolchain_rootfs: data.join("toolchains").join("default.ext4"),
            source_drive: source_img,
            scratch_size_bytes: 256 * 1024 * 1024,
            output_drive: output_img.clone(),
            output_size_bytes: 64 * 1024 * 1024,
            cache_drive: None,
            vcpu_count: 1,
            mem_size_mib: 512,
            vsock_cid: None,
            timeout: Duration::from_secs(60),
            chroot_base: data.join("bj"),
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            uid: 100_000,
            gid: 100_000,
            parent_cgroup: "jkbase-build".into(),
            cgroup_pids_max: 512,
            cgroup_mem_max_bytes: 512 * 1024 * 1024,
            cgroup_cpu_max: "100000 100000".into(),
            fsize_limit_bytes: Some(64 * 1024 * 1024),
            console_log_max_bytes: 1024 * 1024,
            seccomp_filter: None,
            netns: None,
            tap_device: Some(lease.tap.clone()),
            guest_mac: Some(lease.mac.clone()),
            guest_ip: Some(lease.guest_ip.clone()),
            gateway_ip: Some(net.gateway.clone()),
            egress_proxy: Some(net.proxy_url()),
            lang_hint: None,
            fetch_deadline: Duration::from_secs(20),
            seal: Some(make_seal(lease.tap.clone())),
        };
        std::fs::create_dir_all(&cfg.chroot_base).unwrap();

        let run = BuildVm::run("netseal", &cfg, &data.join("run")).await;
        net.release(lease).await;
        let run = run.expect("build VM run");
        assert_eq!(run.outcome, BuildOutcome::Completed, "build VM should complete");

        let read = |name: &str| {
            build_output::read_capped(&output_img, name, 64)
                .ok()
                .flatten()
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .unwrap_or_else(|| "<missing>".into())
        };
        let (allow, block, direct, sealed) =
            (read("/allow"), read("/block"), read("/direct"), read("/sealed"));
        println!("allow={allow} block={block} direct={direct} sealed={sealed}");

        assert_eq!(allow, "200", "allowlisted host must tunnel through the proxy");
        assert_eq!(block, "403", "off-allowlist host must be refused by the proxy");
        assert_eq!(direct, "down", "direct egress must be blocked by the firewall");
        assert_eq!(sealed, "down", "compile phase must be sealed (offline)");
        println!("PASS: networked build — proxy allowlist + firewall + fetch-then-seal");
    }

    /// On-box: a real Bun server is built **through the orchestrator control
    /// plane** — `run_project_build` resolves `language="bun"` →
    /// `select_toolchain` picks `bun.ext4` → the `jkbuild` lifecycle runs
    /// `bun install` in-VM → the flat `/rootfs.tar.gz` + `/manifest.json` are
    /// collected into `staged/_servers/{name}.{tar.gz,json}` with the launch
    /// contract intact (`cmd=[/opt/bun/bin/bun,run,start]`, `working_dir=/app`,
    /// `NODE_ENV=production`). This proves the server-side wiring the
    /// `bun_build_smoke` example exercises only at the build-VM layer. Offline
    /// (no deps), so no egress proxy / seal.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/jkbob JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       <test-bin> --ignored --nocapture bun_server_build_through_orchestrator
    ///
    /// Expects `$JKB_DATA/toolchains/bun.ext4`, a guest kernel at
    /// `$JKB_DATA/vmlinux-6.12.92.bin` (or `vmlinux.bin`), all on one filesystem,
    /// and the parent build cgroup provisioned. Skips cleanly if `bun.ext4` is
    /// absent (toolchain not baked).
    #[tokio::test]
    #[ignore = "needs KVM + root + baked bun.ext4; set JKB_DATA + JKB_FC_RELEASE"]
    async fn bun_server_build_through_orchestrator() {
        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return;
        };
        let toolchain_dir = data.join("toolchains");
        if !toolchain_dir.join("bun.ext4").exists() {
            eprintln!("skip: {}/bun.ext4 not baked", toolchain_dir.display());
            return;
        }
        // Flat rung only needs a bootable kernel; prefer the 6.12 LTS image.
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        };

        // Fixture: a single Bun server, no Dockerfile, no deps. `language="bun"`
        // is the authoritative detect hint (forwarded as `jkbase.lang=bun`).
        let src = data.join("bun-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write(
            src.join("jkbase.toml"),
            r#"
[project]
name = "bunfix"
[servers.api]
source = "./server"
language = "bun"
port = 3000
"#,
        );
        write(
            src.join("server/server.ts"),
            "const port = Number(process.env.PORT) || 3000;\nBun.serve({ port, fetch() { return new Response(\"ok\\n\"); } });\nconsole.log(\"listening on \" + port);\n",
        );
        write(
            src.join("server/package.json"),
            "{\n  \"name\": \"bunfix\",\n  \"module\": \"server.ts\",\n  \"packageManager\": \"bun@1.1.45\",\n  \"scripts\": { \"start\": \"bun run server.ts\" }\n}\n",
        );

        let mut tarbuf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarbuf, flate2::Compression::fast());
            let mut tb = tar::Builder::new(enc);
            tb.append_dir_all(".", &src).unwrap();
            tb.into_inner().unwrap().finish().unwrap();
        }

        let store = Store::open(&data.join("onbox-bun.redb")).unwrap();
        let (project_id, build_id) = ("bunfix", 1u64);
        store
            .save_build(&BuildRecord {
                project_id: project_id.into(),
                build_id,
                phase: BuildPhase::Building,
                targets: vec![],
                log_tail: String::new(),
                phase_timings_ms: Default::default(),
                deployed_version: None,
                error: None,
                source_commit: None,
                created_at: now(),
                updated_at: now(),
            })
            .unwrap();

        let deps = Arc::new(BuildDeps {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel,
            data_dir: data.clone(),
            deploy_dir: data.join("hosting"),
            toolchain_dir,
            store: store.clone(),
            chroot_base: data.join("bj-bun"),
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            parent_cgroup: "jkbase-build".into(),
            uid: 100_000,
            gid: 100_000,
            timeout: Duration::from_secs(120),
            vcpu_count: 2,
            mem_size_mib: 1024,
            cgroup_pids_max: 512,
            // Headroom above the 1 GiB guest so the bun build is not host-OOM-killed.
            cgroup_mem_max_bytes: 1536 * 1024 * 1024,
            cgroup_cpu_max: "200000 100000".into(),
            scratch_size_bytes: 256 * 1024 * 1024,
            output_size_bytes: 64 * 1024 * 1024,
            console_log_max_bytes: 1024 * 1024,
            max_concurrent: 1,
            net: None,
            fetch_deadline: Duration::from_secs(120),
        });
        std::fs::create_dir_all(&deps.chroot_base).unwrap();

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone())
            .await
            .expect("bun server build should succeed");

        // Flat server artifact assembled into the deploy shape.
        assert!(staged.join("_servers/api.tar.gz").exists(), "api rootfs tarball");

        // Manifest = jkbuild launch contract + jkbase.toml port.
        let mani: serde_json::Value =
            serde_json::from_slice(&std::fs::read(staged.join("_servers/api.json")).unwrap())
                .unwrap();
        assert_eq!(mani["port"], 3000);
        assert_eq!(
            mani["cmd"],
            serde_json::json!(["/opt/bun/bin/bun", "run", "start"]),
            "absolute Bun launch command"
        );
        assert_eq!(mani["working_dir"], "/app");
        assert_eq!(mani["env"]["NODE_ENV"], "production");

        // Per-target progress + billing recorded.
        let rec = store.get_build(project_id, build_id).unwrap().unwrap();
        assert_eq!(rec.targets.len(), 1);
        assert_eq!(rec.targets[0].phase, BuildPhase::Succeeded);
        let month_start = jkbase_control::store::month_start_epoch(now());
        let billed = store
            .sum_month_to_date(project_id, month_start)
            .unwrap()
            .build_seconds;
        assert!(billed >= 1, "expected ≥1 build-second, got {billed}");

        let _ = std::fs::remove_dir_all(&staged);
        println!("PASS: run_project_build drove bun.ext4 -> flat server artifact + launch manifest");
    }
}
