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

use anyhow::{bail, ensure, Context, Result};
use jkbase_common::config::{Builder, ProjectConfig};
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

/// Minimum scratch/output drive sizes for a `builder = "dockerfile"` build. A
/// Dockerfile build stores, on the scratch drive, the pulled base-image layers +
/// the container-storage overlay + the `buildah mount` merged rootfs + the erofs
/// blob — far more than a thin buildpack app layer — and the output blob is a full
/// self-contained image rootfs. The thin-buildpack defaults (≈4 GiB scratch /
/// 1 GiB output) SIGXFSZ-kill a `FROM node:20` + `npm ci` build opaquely, so
/// dockerfile builds get materially more room (the backing files are sparse, so an
/// unused budget costs little). Tunable upward via the BuildDeps defaults.
const DOCKERFILE_MIN_SCRATCH_BYTES: u64 = 16 * 1024 * 1024 * 1024; // 16 GiB
const DOCKERFILE_MIN_OUTPUT_BYTES: u64 = 6 * 1024 * 1024 * 1024; // 6 GiB
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
    /// Per-`(project,language)` locks serializing the shared warm-cache image:
    /// `build_vm` MOVES the single image into the jail + back, so two concurrent
    /// same-key targets would race the path. Entries created lazily; bounded by
    /// project×language cardinality (never evicted). The `LogShipper::project_lock`
    /// pattern.
    pub cache_locks: Arc<tokio::sync::Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>>,
    /// Sparse logical size of a per-`(project,language)` build cache image (`vde`);
    /// grows on demand, billed by ACTUAL blocks against the project storage quota.
    pub cache_size_bytes: u64,
    /// The in-VM agent binary (musl, runs on the host too). Used to AOT-precompile a
    /// built function `.wasm` → sibling `.cwasm` (`--precompile`) so the runtime VM
    /// deserializes at boot instead of recompiling the multi-MB JS component. `None`
    /// disables it (the agent falls back to compiling the `.wasm`).
    pub agent_bin: Option<PathBuf>,
}

/// Get-or-create the per-`(project,language)` cache lock (the `LogShipper::project_lock`
/// pattern). Held across a target's `BuildVm::run` so the cache image is never
/// moved into two jails at once.
async fn cache_lock(deps: &BuildDeps, key: &str) -> Arc<tokio::sync::Mutex<()>> {
    deps.cache_locks
        .lock()
        .await
        .entry(key.to_string())
        .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
        .clone()
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
    // Functions use ONE per-kind toolchain image (cargo + wasm32-wasip2 + the JS
    // componentizer), never a per-language *server* image — a Rust function must never
    // grab the server `rust.ext4` (no wasm target, no cargo-component): it would build a
    // native binary, not a `wasi:http` component. Only the server path keys the image on
    // language; the in-VM function-builder dispatches on language itself.
    if kind_name != "function"
        && let Some(lang) = language.filter(|l| !l.is_empty())
    {
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
    // Bun first — its markers are specific (a bun project also carries package.json).
    if has("bun.lockb") || has("bun.lock") || has("bunfig.toml") {
        return Some("bun".to_string());
    }
    if let Ok(pkg) = std::fs::read_to_string(source_path.join("package.json")) {
        if pkg.contains("bun@") {
            return Some("bun".to_string());
        }
        // Any other package.json is a Node project (npm/pnpm/yarn). The in-VM
        // buildpack does the authoritative detect + picks the package manager.
        return Some("node".to_string());
    }
    // A Cargo.toml (and no JS manifest above) is a Rust project.
    if has("Cargo.toml") {
        return Some("rust".to_string());
    }
    // A go.mod is a Go project (checked before Python so a polyglot repo carrying both
    // a go.mod and a stray requirements.txt resolves to the compiled language).
    if has("go.mod") {
        return Some("go".to_string());
    }
    // A pip-installable Python manifest (none of the above matched) is a Python
    // project. Markers match the in-VM buildpack's detect exactly (requirements.txt /
    // pyproject.toml / setup.py) — a Pipfile-only or bare-setup.cfg tree is NOT claimed
    // (pip can't build those; claiming them would ship a deps-less app).
    if has("requirements.txt") || has("pyproject.toml") || has("setup.py") {
        return Some("python".to_string());
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
    /// The public-any egress proxy port (allowlist bypassed, SSRF pin retained),
    /// used only by `builder = "dockerfile"` builds. `None` (or equal to
    /// `proxy_port`) → dockerfile builds share the narrow allowlist proxy.
    pub proxy_any_port: Option<u16>,
    subnet_prefix: String,
    uid: u32,
    pool_size: u8,
    // std (not tokio) Mutex: the critical sections are tiny pop/push with no await,
    // and NetLease's Drop safety-net must return the slot synchronously.
    free_slots: std::sync::Mutex<Vec<u8>>,
    /// Serializes ALL JKBUILD mutations (install/clear of per-lease rules) within
    /// this process. Builds fan out concurrently (semaphore-bounded) and each touches
    /// iptables, so without this two acquires/releases could interleave their rule
    /// edits. Paired with `iptables -w` (which serializes against OTHER processes —
    /// e.g. the ExecStartPre firewall script — via the xtables lock), this makes the
    /// revoke path reliable rather than silently fail-open on lock contention.
    fw_lock: Mutex<()>,
}

/// A leased build-network slot (its TAP + guest IP/MAC); returned via [`BuildNet::release`].
pub struct NetLease {
    /// Back-reference for the `Drop` safety-net (return the slot, revoke the grant).
    net: Arc<BuildNet>,
    slot: u8,
    tap: String,
    guest_ip: String,
    mac: String,
    /// Whether this lease was granted a per-source ACCEPT to the public-any
    /// (dockerfile) egress proxy port, so [`BuildNet::release`] revokes exactly
    /// what [`BuildNet::acquire`] installed.
    any_egress: bool,
    /// Set by the explicit async [`BuildNet::release`] so `Drop` doesn't double-clean.
    released: bool,
}

impl Drop for NetLease {
    fn drop(&mut self) {
        if self.released {
            return; // the explicit async release already cleaned up.
        }
        // Safety net: a panic or runtime cancellation skipped the explicit release.
        // Best-effort BLOCKING cleanup so a dropped build can't leak its slot
        // (pool-exhaustion DoS) or its :3129 grant. No fw_lock (can't .await in Drop);
        // each `iptables -w -D` is atomic under the xtables lock, enough for a
        // single-rule revoke.
        if self.any_egress
            && let Some(any_port) = self.net.proxy_any_port
        {
            let spec = self.net.any_egress_rule(&self.guest_ip, any_port);
            for _ in 0..8 {
                // Bounded `-w 5`: Drop is blocking + uncancellable, so a contended
                // xtables lock must not pin this worker thread indefinitely.
                let mut args = vec![
                    "-w".to_string(),
                    "5".to_string(),
                    "-D".to_string(),
                    "JKBUILD".to_string(),
                ];
                args.extend(spec.iter().cloned());
                let removed = std::process::Command::new("iptables")
                    .args(&args)
                    .status()
                    .map(|s| s.success())
                    .unwrap_or(false);
                if !removed {
                    break;
                }
            }
        }
        let _ = std::process::Command::new("ip")
            .args(["link", "delete", &self.tap])
            .status();
        if let Ok(mut slots) = self.net.free_slots.lock() {
            slots.push(self.slot);
        }
    }
}

impl BuildNet {
    /// `pool_size` concurrent slots → guest IPs `<subnet>.2 ..= .(1+pool_size)`.
    pub fn new(
        bridge: String,
        gateway: String,
        proxy_port: u16,
        proxy_any_port: Option<u16>,
        uid: u32,
        pool_size: u8,
    ) -> Self {
        let subnet_prefix = {
            let mut parts: Vec<&str> = gateway.split('.').collect();
            parts.truncate(3);
            parts.join(".")
        };
        // A distinct port enables the public-any proxy; equal/absent disables it.
        let proxy_any_port = proxy_any_port.filter(|p| *p != proxy_port);
        // Reversed so pop() hands out ascending slot numbers.
        let free_slots: Vec<u8> = (1..=pool_size).rev().collect();
        Self {
            bridge,
            gateway,
            proxy_port,
            proxy_any_port,
            subnet_prefix,
            uid,
            pool_size,
            free_slots: std::sync::Mutex::new(free_slots),
            fw_lock: Mutex::new(()),
        }
    }

    pub fn proxy_url(&self) -> String {
        format!("http://{}:{}", self.gateway, self.proxy_port)
    }

    /// The egress proxy URL to hand a build VM. Dockerfile builds get the public-any
    /// proxy (when configured); everything else gets the narrow allowlist proxy.
    pub fn proxy_url_for(&self, is_dockerfile: bool) -> String {
        match (is_dockerfile, self.proxy_any_port) {
            (true, Some(port)) => format!("http://{}:{}", self.gateway, port),
            _ => self.proxy_url(),
        }
    }

    /// Lease a slot and bring up its TAP — owned by the build uid (so the jailed
    /// firecracker can open it) and mastered to the build bridge.
    ///
    /// `allow_any_egress` (dockerfile builds) grants THIS lease's guest IP — and
    /// only it — a per-source firewall rule to the public-any egress proxy. The
    /// firewall opens the public-any port to no one by default, so a hostile
    /// non-dockerfile build can't ignore its assigned narrow proxy and reach broad
    /// egress directly: the in-guest `jkbase.proxy=` boot-arg is only a hint, and
    /// the guest is untrusted, so the network layer is the real boundary.
    pub async fn acquire(self: &Arc<Self>, allow_any_egress: bool) -> Result<NetLease> {
        let slot = {
            let mut slots = self.free_slots.lock().unwrap();
            slots
                .pop()
                .ok_or_else(|| anyhow::anyhow!("build network pool exhausted"))?
        };
        let tap = format!("jkbld{slot}");
        let guest_ip = format!("{}.{}", self.subnet_prefix, slot as u16 + 1);
        let mac = format!("AA:FC:00:1F:00:{slot:02X}");
        if let Err(e) = self.setup_tap(&tap).await {
            self.free_slots.lock().unwrap().push(slot);
            return Err(e);
        }
        // Per-VM public-any scoping. Slots (hence guest IPs) are reused, so a
        // crashed dockerfile lease could leave a stale grant that a later
        // non-dockerfile lease on the same IP would inherit — always clear first,
        // then grant only for a dockerfile lease. A no-op when the public-any proxy
        // is unconfigured (`proxy_any_port` None), so non-activated boxes are
        // unchanged.
        let mut any_egress = false;
        if let Some(any_port) = self.proxy_any_port {
            let _fw = self.fw_lock.lock().await;
            self.clear_any_egress(&guest_ip, any_port).await;
            if allow_any_egress {
                if let Err(e) = self.install_any_egress(&guest_ip, any_port).await {
                    // Fail closed: roll back the TAP + slot rather than boot a VM
                    // that can't reach the proxy it was told to use.
                    let _ = run_ip(&["link", "delete", &tap]).await;
                    self.free_slots.lock().unwrap().push(slot);
                    return Err(e);
                }
                any_egress = true;
            }
        }
        Ok(NetLease {
            net: Arc::clone(self),
            slot,
            tap,
            guest_ip,
            mac,
            any_egress,
            released: false,
        })
    }

    /// Tear the leased TAP down (idempotent — the seal may already have deleted
    /// it), revoke any per-lease public-any egress grant, and return the slot. Marks
    /// the lease released so its `Drop` safety-net is a no-op.
    pub async fn release(&self, mut lease: NetLease) {
        if lease.any_egress
            && let Some(any_port) = self.proxy_any_port
        {
            let _fw = self.fw_lock.lock().await;
            self.clear_any_egress(&lease.guest_ip, any_port).await;
        }
        let _ = run_ip(&["link", "delete", &lease.tap]).await;
        self.free_slots.lock().unwrap().push(lease.slot);
        lease.released = true;
    }

    /// The JKBUILD rule spec (sans verb) granting ONE guest IP reach to the
    /// public-any (dockerfile) egress proxy port. Kept exact so the `-I` (install)
    /// and `-D` (revoke) forms match the same rule.
    fn any_egress_rule(&self, guest_ip: &str, any_port: u16) -> Vec<String> {
        vec![
            "-s".into(),
            guest_ip.to_string(),
            "-p".into(),
            "tcp".into(),
            "-d".into(),
            self.gateway.clone(),
            "--dport".into(),
            any_port.to_string(),
            "-j".into(),
            "ACCEPT".into(),
        ]
    }

    /// Remove EVERY JKBUILD rule granting `guest_ip` the public-any port (there may
    /// be a stale one from a crashed lease on the same, since-reused slot).
    /// Idempotent: loops until `iptables -D` reports no matching rule. `-w` makes the
    /// "no match" verdict trustworthy — without it, losing the xtables lock to a
    /// concurrent edit returns the same nonzero exit as "rule absent", which would
    /// silently leave a stale grant installed (a fail-open in the revoke path). Call
    /// under `fw_lock` so this process's own edits never contend.
    async fn clear_any_egress(&self, guest_ip: &str, any_port: u16) {
        let spec = self.any_egress_rule(guest_ip, any_port);
        for _ in 0..64 {
            let mut args = vec!["-w".to_string(), "-D".to_string(), "JKBUILD".to_string()];
            args.extend(spec.iter().cloned());
            let removed = tokio::process::Command::new("iptables")
                .args(&args)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !removed {
                break;
            }
        }
    }

    /// Grant ONE dockerfile-build guest IP reach to the public-any proxy. Inserted
    /// at the top of JKBUILD so it precedes the chain's terminal DROP. `-w` waits for
    /// the xtables lock instead of failing the build on contention. Call under
    /// `fw_lock`.
    async fn install_any_egress(&self, guest_ip: &str, any_port: u16) -> Result<()> {
        let mut args = vec![
            "-w".to_string(),
            "-I".to_string(),
            "JKBUILD".to_string(),
            "1".to_string(),
        ];
        args.extend(self.any_egress_rule(guest_ip, any_port));
        let status = tokio::process::Command::new("iptables")
            .args(&args)
            .status()
            .await
            .context("install per-lease public-any egress rule")?;
        if !status.success() {
            bail!("iptables -I JKBUILD (per-lease public-any egress) failed for {guest_ip}");
        }
        Ok(())
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
        // FATAL: the isolation rules. Without these a build VM could reach the host
        // / other VMs / the internet — refuse to run builds at all.
        let input_hook = ["-w", "-C", "INPUT", "-i", self.bridge.as_str(), "-j", "JKBUILD"];
        let fwd_drop = ["-w", "-C", "FORWARD", "-i", self.bridge.as_str(), "-j", "DROP"];
        for check in [input_hook, fwd_drop] {
            let ok = tokio::process::Command::new("iptables")
                .args(check)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if !ok {
                bail!(
                    "build firewall isolation rule missing ({check:?}) — run `sudo tools/setup-build-net.sh`"
                );
            }
        }
        // FATAL (only when the public-any proxy is configured): a *blanket*
        // (any-source) ACCEPT for the public-any port means EVERY build VM can reach
        // broad egress — exactly the hole the per-lease scoping closes. A lingering
        // old `setup-build-net.sh` that opens it to all sources would silently defeat
        // the isolation, so refuse to start if such a rule is present. (The per-lease
        // grants carry `-s <guest_ip>`, which `-C` without `-s` will NOT match, so
        // this only trips on a truly source-unrestricted rule.)
        if let Some(any) = self.proxy_any_port {
            let blanket = [
                "-w", "-C", "JKBUILD", "-p", "tcp", "-d", self.gateway.as_str(),
                "--dport", &any.to_string(), "-j", "ACCEPT",
            ];
            let present = tokio::process::Command::new("iptables")
                .args(blanket)
                .status()
                .await
                .map(|s| s.success())
                .unwrap_or(false);
            if present {
                bail!(
                    "build firewall opens the public-any proxy port {any} to ALL build VMs \
                     (source-unrestricted ACCEPT in JKBUILD) — this defeats per-dockerfile-VM \
                     egress scoping. Re-sync + re-run `sudo tools/setup-build-net.sh` (it no \
                     longer adds a blanket rule for this port)."
                );
            }
        }
        // WARN-only: the narrow allowlist proxy ACCEPT is about FUNCTIONALITY (can a
        // build reach the egress proxy), not isolation — a missing one makes builds
        // fail at fetch (fail-safe), so surface it loudly but don't refuse to start
        // (and never outage the runtime over an iptables rule-form mismatch).
        let proxy_accept = [
            "-w", "-C", "JKBUILD", "-p", "tcp", "-d", self.gateway.as_str(),
            "--dport", &self.proxy_port.to_string(), "-j", "ACCEPT",
        ];
        let ok = tokio::process::Command::new("iptables")
            .args(proxy_accept)
            .status()
            .await
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            warn!(
                gateway = %self.gateway, port = self.proxy_port,
                "build firewall: no ACCEPT rule for the egress proxy port — builds will get no egress; run `sudo tools/setup-build-net.sh`"
            );
        }
        Ok(())
    }

    /// Install the L2 source-guard that makes the per-lease `-s <ip>` :3129 grant
    /// un-spoofable. Build VMs share one bridge with the gateway, and bridge port
    /// isolation only blocks VM↔VM — a hostile guest can still emit frames toward the
    /// gateway bearing ANOTHER VM's source IP, which an iptables `-s` rule would
    /// honour (defeating per-dockerfile-VM scoping). ebtables sees the real L2 ingress
    /// TAP (no br_netfilter / physdev needed), so we pin each slot's TAP to its
    /// assigned source MAC + IPv4 source + ARP source: a frame on `jkbld<N>` not
    /// bearing slot N's identity is dropped before iptables ever sees it.
    ///
    /// Static per-slot (ebtables accepts rules for not-yet-created TAPs), so there is
    /// no per-build L2 churn. Idempotent (re-flushes + repopulates on each startup).
    /// No-op — and no ebtables dependency exercised — when the public-any proxy is
    /// unconfigured, so non-activated boxes are unchanged. FAIL-CLOSED when activated:
    /// running the per-VM :3129 scoping without this guard is the spoofable state, so
    /// refuse to start if it can't be installed.
    pub async fn ensure_source_guard(&self) -> Result<()> {
        if self.proxy_any_port.is_none() {
            return Ok(());
        }
        // (Re)create the chain empty for idempotency (ignore "already exists").
        let _ = run_ebtables(&["-t", "filter", "-N", SOURCE_GUARD_CHAIN]).await;
        run_ebtables(&["-t", "filter", "-F", SOURCE_GUARD_CHAIN])
            .await
            .context(
                "flush ebtables source-guard chain (is `ebtables` installed? it is \
                 required when --build-proxy-any-port is set)",
            )?;
        for slot in 1..=self.pool_size {
            let tap = format!("jkbld{slot}");
            let ip = format!("{}.{}", self.subnet_prefix, slot as u16 + 1);
            let mac = format!("AA:FC:00:1F:00:{slot:02X}");
            // DROP frames on this TAP not bearing slot N's source MAC / IPv4 src / ARP src.
            // First, DROP any 802.1Q VLAN-tagged frame outright: `-p IPv4`/`-p ARP` match
            // the OUTER ethertype, so a tagged frame (0x8100) would skip the IP/ARP source
            // pins. Build VMs have no VLAN use case, so this closes that bypass at the
            // source rather than relying on the host never decapsulating VLAN tags.
            run_ebtables(&[
                "-t", "filter", "-A", SOURCE_GUARD_CHAIN, "-i", tap.as_str(), "-p", "802_1Q",
                "-j", "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t", "filter", "-A", SOURCE_GUARD_CHAIN, "-i", tap.as_str(), "!", "-s",
                mac.as_str(), "-j", "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t", "filter", "-A", SOURCE_GUARD_CHAIN, "-i", tap.as_str(), "-p", "IPv4",
                "!", "--ip-src", ip.as_str(), "-j", "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t", "filter", "-A", SOURCE_GUARD_CHAIN, "-i", tap.as_str(), "-p", "ARP",
                "!", "--arp-ip-src", ip.as_str(), "-j", "DROP",
            ])
            .await?;
        }
        // Hook into the L2 INPUT (frames to the gateway/host) + FORWARD (VM↔VM, already
        // isolated — defense in depth) paths, once each. Rules match `-i jkbld*`, so
        // frames from the runtime bridge fall straight through with no effect.
        for hook in ["INPUT", "FORWARD"] {
            if !ebtables_ok(&["-t", "filter", "-C", hook, "-j", SOURCE_GUARD_CHAIN]).await {
                run_ebtables(&["-t", "filter", "-I", hook, "-j", SOURCE_GUARD_CHAIN])
                    .await
                    .with_context(|| format!("hook source-guard into ebtables {hook}"))?;
            }
        }
        info!(
            pool = self.pool_size,
            "build L2 source-guard installed (per-VM source IP/MAC pinning)"
        );
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

/// The ebtables (L2/bridge filter) chain holding the per-VM source-guard rules.
const SOURCE_GUARD_CHAIN: &str = "JKBUILD_SG";

/// Run an ebtables command, erroring on failure. ebtables is only invoked by this
/// process (the firewall script stays iptables-only), so `fw_lock` / startup
/// single-threading already serialize edits — no `--concurrent` needed.
async fn run_ebtables(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .context("spawn ebtables")?;
    if !status.success() {
        bail!("ebtables {args:?} failed: {status}");
    }
    Ok(())
}

/// True iff the ebtables command succeeds — for `-C` existence checks; never errors.
async fn ebtables_ok(args: &[&str]) -> bool {
    tokio::process::Command::new("ebtables")
        .args(args)
        .status()
        .await
        .map(|s| s.success())
        .unwrap_or(false)
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
    /// Build strategy (`auto` buildpack detect, or the `dockerfile` escape hatch).
    builder: Builder,
    /// Dockerfile path relative to `source_subdir` (i.e. relative to `/src` in the
    /// VM), for `builder = "dockerfile"`. `None` otherwise.
    dockerfile: Option<String>,
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
        Ok((log, provenance)) => {
            update_target(
                deps,
                record_lock,
                project_id,
                build_id,
                &spec.name,
                BuildPhase::Succeeded,
                |t| {
                    t.finished_at = Some(now());
                    t.cache_hit = provenance.cache_hit;
                    t.cache_key = provenance.cache_key.clone();
                    t.duration_breakdown_ms = provenance.duration_breakdown_ms.clone();
                    t.builder_digest = provenance.builder_digest.clone();
                },
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
) -> Result<(Option<Vec<u8>>, BuildProvenance)> {
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
    // Dockerfile builds pick the dedicated `dockerfile` toolchain image (buildah &c.)
    // and do NOT language-detect (a Dockerfile carries its own runtime). The in-VM
    // lifecycle is steered by `jkbase.builder`, not `jkbase.lang`.
    let is_dockerfile = spec.builder == Builder::Dockerfile;
    let (toolchain_lang, lang_hint): (Option<String>, Option<String>) = if is_dockerfile {
        (Some("dockerfile".to_string()), None)
    } else {
        // Resolve the language: the explicit jkbase.toml hint, else a cheap host-side
        // sniff of the source (the in-VM lifecycle does the authoritative detect).
        let l = detect_language(&source_path, spec.language.as_deref());
        (l.clone(), l)
    };
    let toolchain = deps
        .select_toolchain(spec.kind, toolchain_lang.as_deref())
        .ok_or_else(|| {
            anyhow::anyhow!(
                "no toolchain image for {}{} in {}",
                kind_name(spec.kind),
                toolchain_lang
                    .as_deref()
                    .map(|l| format!("/{l}"))
                    .unwrap_or_default(),
                deps.toolchain_dir.display()
            )
        })?;

    // A `builder = "dockerfile"` build MUST resolve to the real dockerfile toolchain
    // (buildah &c.). `select_toolchain` falls back through `<kind>.ext4`/`default.ext4`
    // when `dockerfile.ext4` is absent — but a busybox passthrough can't build a
    // Dockerfile, and (critically) we must NOT hand that fallback VM the public-any
    // (:3129) egress grant keyed on the raw builder flag: that would arm broad egress
    // for a build the operator never provisioned the feature for. Fail clearly here so
    // `is_dockerfile` past this point implies the dockerfile toolchain actually ran.
    let resolved_dockerfile =
        toolchain.file_name().and_then(|s| s.to_str()) == Some("dockerfile.ext4");
    if is_dockerfile && !resolved_dockerfile {
        bail!(
            "builder = \"dockerfile\" requires the dockerfile build toolchain \
             (dockerfile.ext4), which is not provisioned in {}",
            deps.toolchain_dir.display()
        );
    }

    let tag = format!("{}-{}", kind_name(spec.kind), sanitize(&spec.name));
    let source_img = workspace.join(format!("{tag}.source.img"));
    let output_img = workspace.join(format!("{tag}.output.img"));

    // Dockerfile builds need a much bigger scratch/output budget (base layers +
    // container overlay + merged mount + image blob) than a thin buildpack layer.
    let (scratch_size_bytes, output_size_bytes) = if is_dockerfile {
        (
            deps.scratch_size_bytes.max(DOCKERFILE_MIN_SCRATCH_BYTES),
            deps.output_size_bytes.max(DOCKERFILE_MIN_OUTPUT_BYTES),
        )
    } else {
        (deps.scratch_size_bytes, deps.output_size_bytes)
    };

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
        Some(net) => Some(
            net.acquire(is_dockerfile)
                .await
                .context("acquire build network")?,
        ),
        None => None,
    };
    let (tap_device, guest_mac, guest_ip, gateway_ip, egress_proxy, seal) =
        match (&deps.net, &lease) {
            (Some(net), Some(l)) => (
                Some(l.tap.clone()),
                Some(l.mac.clone()),
                Some(l.guest_ip.clone()),
                Some(net.gateway.clone()),
                Some(net.proxy_url_for(is_dockerfile)),
                Some(make_seal(l.tap.clone())),
            ),
            _ => (None, None, None, None, None, None),
        };

    // Per-`(project,language)` persistent warm cache (the `vde` drive): cargo
    // registry/git, npm/pnpm/yarn stores, etc. survive across builds for fast
    // rebuilds. Skipped for dockerfile builds (the image carries its own cache) and
    // when no language resolves pre-boot (can't pick the per-language image — the
    // guest's tmpfs `/cache` fallback covers that case). The image is moved into the
    // jail + back by `build_vm`, so we hold the per-key lock across the whole target
    // build to serialize same-`(project,language)` targets (rare: usually one server
    // per language); cross-key and cross-project builds still run in parallel.
    let cache_target = (!is_dockerfile)
        .then_some(toolchain_lang.as_deref())
        .flatten()
        .map(sanitize)
        .filter(|l| !l.is_empty());
    let mut _cache_guard = None;
    let cache_drive = if let Some(lang) = &cache_target {
        let lock = cache_lock(deps, &format!("{project_id}/{lang}")).await;
        _cache_guard = Some(lock.lock_owned().await);
        let path = deps
            .data_dir
            .join("buildcache")
            .join(project_id)
            .join(format!("{lang}.img"));
        // create-once under the lock (no concurrent creation).
        match jkbase_orch::build_image::build_empty_ext4(
            &path,
            deps.cache_size_bytes,
            deps.uid,
            deps.gid,
        ) {
            Ok(()) => Some(path),
            Err(e) => {
                warn!(project = %project_id, lang = %lang, error = %e,
                      "could not provision build cache image; building without a warm cache");
                None
            }
        }
    } else {
        None
    };

    let cfg = BuildVmConfig {
        jailer_bin: deps.jailer_bin.clone(),
        firecracker_bin: deps.firecracker_bin.clone(),
        kernel_path: deps.kernel_path.clone(),
        // Clone the path (cheap) so the success path can hash the toolchain image for
        // `builder_digest` provenance after the VM has consumed the config.
        toolchain_rootfs: toolchain.clone(),
        source_drive: source_img.clone(),
        scratch_size_bytes,
        output_drive: output_img.clone(),
        output_size_bytes,
        cache_drive: cache_drive.clone(),
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
        // the fixed output-drive size; the cache image's logical size must be
        // covered too when one is attached.
        fsize_limit_bytes: Some(
            scratch_size_bytes
                .max(output_size_bytes)
                .max(if cache_drive.is_some() { deps.cache_size_bytes } else { 0 }),
        ),
        console_log_max_bytes: deps.console_log_max_bytes,
        seccomp_filter: None,
        netns: None,
        tap_device,
        guest_mac,
        guest_ip,
        gateway_ip,
        egress_proxy,
        lang_hint,
        // Layered: the in-VM exporter emits the app erofs layer + index.json; the
        // host collection arm (below) dumps + sha256-verifies it. The runtime
        // overlays it on the shared base/runtime layers (or, for a dockerfile build,
        // runs the single self-contained app layer with no base/runtime).
        export_layered: true,
        // Function targets run the in-VM function-builder (→ /out/function.wasm), which
        // ignores the server export mode above.
        build_function: matches!(spec.kind, TargetKind::Function),
        builder_hint: is_dockerfile.then(|| "dockerfile".to_string()),
        dockerfile: spec.dockerfile.clone(),
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
        BuildOutcome::Crashed { code, signal } => {
            // Firecracker's RLIMIT_FSIZE is process-wide: a guest write past the
            // scratch/output budget SIGXFSZ-kills the VM (signal 25 on Linux). Give
            // the tenant an actionable "ran out of build space" instead of an opaque
            // crash that reads like an OOM/panic.
            const SIGXFSZ: i32 = 25;
            if signal == Some(SIGXFSZ) {
                let gib = |b: u64| format!("{:.1} GiB", b as f64 / (1u64 << 30) as f64);
                let hint = if is_dockerfile {
                    " — the image or its intermediate layers are too large; trim the build (fewer/smaller layers, multi-stage, prune caches)"
                } else {
                    " — try `builder = \"dockerfile\"` (a much larger build budget) or trim dependencies"
                };
                bail!(
                    "build exceeded its disk budget (scratch {} / output {}){}\n{}",
                    gib(scratch_size_bytes),
                    gib(output_size_bytes),
                    hint,
                    log_str()
                );
            }
            bail!(
                "build VM crashed (code={code:?}, signal={signal:?}) — likely cgroup OOM-kill or panic\n{}",
                log_str()
            )
        }
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
            // Best-effort AOT precompile to a sibling `.cwasm`, moving the (multi-second,
            // for the big JS engine) component compile off the runtime VM's boot/wake path
            // to here. Non-fatal: the agent falls back to compiling the `.wasm` if the
            // `.cwasm` is absent or CPU/version-incompatible.
            if let Some(agent_bin) = deps.agent_bin.clone() {
                let wasm = dest.clone();
                let cwasm = dest.with_extension("cwasm");
                let _ = tokio::task::spawn_blocking(move || {
                    precompile_function(&agent_bin, &wasm, &cwasm)
                })
                .await;
            }
        }
        TargetKind::Server => {
            collect_layered_server(
                &output_img,
                staged,
                workspace,
                &tag,
                config,
                spec,
                toolchain_lang.as_deref(),
            )?;
        }
    }

    // Fold provenance into the target record: the exporter's cache outcome/timings
    // (best-effort — defaults until the in-VM cache keying lands) and the sha256 of
    // the toolchain image this target built with. Provenance must never fail a build
    // that otherwise succeeded, so a digest error degrades to None.
    let cache = read_cache_meta(&output_img, workspace, &tag);
    let provenance = BuildProvenance {
        cache_hit: cache.cache_hit,
        cache_key: cache.cache_key,
        duration_breakdown_ms: cache.phases_ms,
        builder_digest: toolchain_builder_digest(&toolchain).await,
    };

    Ok((log_tail, provenance))
}

/// Collect a layered server build: read `/layers/index.json`, dump + sha256-verify
/// the (untrusted) app erofs layer into the deployment's `_layers/`, and write the
/// server manifest augmented with the layer refs the host deploy path needs
/// (`app_layer` filename + `runtime` language). The shared base/runtime layers are
/// injected host-side by digest, not carried in the tenant's build output.
/// Run `jkbase-agent --precompile <wasm> <cwasm>` (host-side; the agent is a musl static
/// binary). Best-effort: on any failure the `.cwasm` is removed and the runtime compiles
/// the `.wasm` at boot, so functions still work — this only trades a slow first boot for a
/// slower deploy.
fn precompile_function(agent_bin: &Path, wasm: &Path, cwasm: &Path) {
    match std::process::Command::new(agent_bin)
        .arg("--precompile")
        .arg(wasm)
        .arg(cwasm)
        .output()
    {
        Ok(out) if out.status.success() => {
            info!(wasm = %wasm.display(), "precompiled function → .cwasm");
        }
        Ok(out) => {
            warn!(
                wasm = %wasm.display(),
                stderr = %String::from_utf8_lossy(&out.stderr).trim(),
                "function precompile failed (non-fatal; compiles at boot)"
            );
            let _ = std::fs::remove_file(cwasm);
        }
        Err(e) => {
            warn!(wasm = %wasm.display(), error = %e, "could not run agent --precompile (non-fatal)");
        }
    }
}

fn collect_layered_server(
    output_img: &Path,
    staged: &Path,
    workspace: &Path,
    tag: &str,
    config: &ProjectConfig,
    spec: &TargetSpec,
    // The language the host resolved for this target (explicit jkbase.toml hint or
    // the cheap source sniff) — keys the shared runtime layer the app stacks on.
    resolved_language: Option<&str>,
) -> Result<()> {
    // Read the layered index the in-VM exporter wrote.
    let index_tmp = workspace.join(format!("{tag}.index.json"));
    if !build_output::dump_file(output_img, jkbuild_types::out::INDEX, &index_tmp)? {
        bail!("server build produced no {} (expected a layered export)", jkbuild_types::out::INDEX);
    }
    let index: jkbuild_types::Index = serde_json::from_slice(&std::fs::read(&index_tmp)?)
        .context("parse layers/index.json from the build output")?;
    let _ = std::fs::remove_file(&index_tmp);

    // The buildpack emits exactly one app layer (base/runtime are host-injected).
    let app = index
        .layers
        .iter()
        .find(|l| l.role == jkbuild_types::LayerRole::App)
        .ok_or_else(|| anyhow::anyhow!("layered build has no app layer in index.json"))?;
    ensure!(app.media == "erofs", "unexpected app layer media {:?}", app.media);

    // The blob filename becomes a dest path — it is fully attacker-controlled, so
    // bound it to `sha256-<64hex>.erofs` (no separators, no traversal).
    let file = app.file.clone();
    ensure!(is_safe_blob_filename(&file), "unsafe app layer filename {file:?}");

    let layers_dir = staged.join("_layers");
    std::fs::create_dir_all(&layers_dir)?;
    let blob_dest = layers_dir.join(&file);
    if !build_output::dump_file(output_img, &format!("/layers/{file}"), &blob_dest)? {
        bail!("layered build missing blob {file} referenced by index.json");
    }

    // sha256-verify the dumped blob against the index digest (all tenants untrusted).
    let want = app.digest.strip_prefix("sha256:").unwrap_or(&app.digest);
    let got = sha256_hex(&blob_dest)?;
    ensure!(
        got.eq_ignore_ascii_case(want),
        "app layer digest mismatch: index {want}, dumped blob {got}"
    );

    // Server manifest: build-derived cmd/env/working_dir overlaid with the
    // jkbase.toml port/health_check/volumes, augmented with the layer refs.
    let built = read_built_manifest(output_img, workspace, tag)?;
    let server_cfg = config
        .servers
        .get(&spec.name)
        .ok_or_else(|| anyhow::anyhow!("server '{}' missing from config", spec.name))?;
    // The jkbase.toml `command` override wins over the buildpack-derived start; the
    // override also covers apps where no start is auto-derivable (the buildpack now
    // leaves an empty cmd rather than failing). If there is NO command from either
    // source, fail here — clearly — rather than ship a server that can't launch.
    let cmd = server_cfg.command.clone().unwrap_or(built.cmd);
    if cmd.is_empty() {
        bail!(
            "server '{0}' has no start command: add a `start` script to its package.json, \
             a server entrypoint (server.ts/index.ts), or `command = [\"...\"]` under [servers.{0}]",
            spec.name
        );
    }
    let mut manifest = server_cfg.manifest_value(cmd, built.env, &built.working_dir);
    if let Some(obj) = manifest.as_object_mut() {
        obj.insert("app_layer".to_string(), serde_json::Value::String(file));
        obj.insert("app_digest".to_string(), serde_json::Value::String(app.digest.clone()));
        // A dockerfile build is a single self-contained image layer — mark it so the
        // host layer plan runs it standalone (no base/runtime stack) and the agent
        // honours the image's own env. Otherwise it's a language runtime layer keyed
        // by the RESOLVED language (not the raw jkbase.toml hint, which is usually
        // absent for an auto-detected node/rust app — that would mis-stamp it "bun"
        // and the layer plan would attach the bun runtime under a node/rust binary).
        let runtime = if spec.builder == Builder::Dockerfile {
            crate::layer_plan::IMAGE_SELF_RUNTIME.to_string()
        } else {
            // Filter empties so a `language = ""` in jkbase.toml can't stamp an empty
            // runtime (which would fail compute_layer_plan with "no platform runtime
            // layer for language ''").
            let r = resolved_language
                .filter(|l| !l.is_empty())
                .map(str::to_string)
                .or_else(|| spec.language.clone().filter(|l| !l.is_empty()))
                .unwrap_or_else(|| "bun".to_string());
            // `image/self` is a RESERVED host-only sentinel set solely by the Dockerfile
            // branch above; it marks a self-contained single-layer rootfs that bypasses the
            // shared base/runtime + dm-verity stack. A tenant must not be able to forge it
            // via a jkbase.toml `language = "image/self"` hint (untrusted input → reserved
            // control value). Reject it here; legitimate languages are never this string.
            if r == crate::layer_plan::IMAGE_SELF_RUNTIME {
                anyhow::bail!(
                    "invalid language '{}' for server '{}': reserved platform value",
                    r,
                    spec.name
                );
            }
            r
        };
        obj.insert("runtime".to_string(), serde_json::Value::String(runtime));
    }
    let json = serde_json::to_string_pretty(&manifest)?;
    std::fs::write(staged.join("_servers").join(format!("{}.json", spec.name)), json)?;
    Ok(())
}

/// A content-addressed erofs blob filename: `sha256-<64hex>.erofs`, no separators.
fn is_safe_blob_filename(f: &str) -> bool {
    const PRE: &str = "sha256-";
    const SUF: &str = ".erofs";
    f.len() == PRE.len() + 64 + SUF.len()
        && f.starts_with(PRE)
        && f.ends_with(SUF)
        && f[PRE.len()..f.len() - SUF.len()]
            .chars()
            .all(|c| c.is_ascii_hexdigit())
}

fn sha256_hex(path: &Path) -> Result<String> {
    use sha2::{Digest, Sha256};
    let mut f = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hasher = Sha256::new();
    std::io::copy(&mut f, &mut hasher).with_context(|| format!("hash {}", path.display()))?;
    let out = hasher.finalize();
    let mut s = String::with_capacity(64);
    for b in out {
        use std::fmt::Write;
        let _ = write!(s, "{b:02x}");
    }
    Ok(s)
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

/// Build provenance folded into the target record on success: the cache outcome +
/// per-phase timings the in-VM exporter reports, plus the sha256 of the toolchain
/// image this target built with.
#[derive(Debug, Default)]
struct BuildProvenance {
    cache_hit: bool,
    cache_key: Option<String>,
    duration_breakdown_ms: std::collections::BTreeMap<String, u64>,
    builder_digest: Option<String>,
}

/// Read the in-VM exporter's `/cache.json` ([`jkbuild_types::CacheMeta`]: cache
/// key/hit + per-phase timings), degrading to defaults when it is absent or
/// unparseable. A build without it is valid — the in-VM cache keying may not be
/// populated yet — so this never fails the build over provenance.
fn read_cache_meta(output_img: &Path, workspace: &Path, tag: &str) -> jkbuild_types::CacheMeta {
    let tmp = workspace.join(format!("{tag}.cache.json"));
    let present =
        build_output::dump_file(output_img, jkbuild_types::out::CACHE, &tmp).unwrap_or(false);
    if !present {
        return jkbuild_types::CacheMeta::default();
    }
    let parsed = std::fs::read(&tmp)
        .ok()
        .and_then(|b| serde_json::from_slice::<jkbuild_types::CacheMeta>(&b).ok());
    let _ = std::fs::remove_file(&tmp);
    parsed.unwrap_or_default()
}

/// `sha256:…` of the toolchain image for `builder_digest` provenance, memoized by
/// (path, size, mtime). Toolchain images are large (up to ~1.8 GiB) and stable, so
/// hash once per version rather than on every build, and on the blocking pool (a
/// multi-second hash must not stall a tokio worker). `None` if the image is gone or
/// the hash fails — provenance must never fail a build that otherwise succeeded.
async fn toolchain_builder_digest(toolchain: &Path) -> Option<String> {
    // (size, mtime) → digest, so a re-baked toolchain image (new size/mtime) re-hashes.
    type DigestCache = std::sync::Mutex<HashMap<PathBuf, (u64, std::time::SystemTime, String)>>;
    static CACHE: std::sync::LazyLock<DigestCache> =
        std::sync::LazyLock::new(|| std::sync::Mutex::new(HashMap::new()));

    let meta = std::fs::metadata(toolchain).ok()?;
    let size = meta.len();
    let mtime = meta.modified().ok()?;
    {
        let cache = CACHE.lock().unwrap_or_else(|p| p.into_inner());
        if let Some((s, m, d)) = cache.get(toolchain)
            && *s == size
            && *m == mtime
        {
            return Some(d.clone());
        }
    }
    let path = toolchain.to_path_buf();
    let hex = tokio::task::spawn_blocking(move || sha256_hex(&path))
        .await
        .ok()?
        .ok()?;
    let digest = format!("sha256:{hex}");
    CACHE
        .lock()
        .unwrap_or_else(|p| p.into_inner())
        .insert(toolchain.to_path_buf(), (size, mtime, digest.clone()));
    Some(digest)
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
        // builder = auto|dockerfile, and (for dockerfile) language/dockerfile coherence.
        s.validate(name)?;
        // The Dockerfile must live inside the project tree (it becomes a /src path).
        if s.builder()? == Builder::Dockerfile {
            let df = s.dockerfile_path();
            if !path_ok(&df) {
                bail!("server '{name}' dockerfile {df:?} must be a relative path inside the project (no '..' or absolute)");
            }
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
            builder: Builder::Auto, // functions take the wasm path, never a Dockerfile
            dockerfile: None,
        });
    }
    for (name, s) in &config.servers {
        // `builder` was validated at intake (see run_inner); default to Auto on the
        // (already-rejected) error path rather than panicking here.
        let builder = s.builder().unwrap_or(Builder::Auto);
        let dockerfile = (builder == Builder::Dockerfile)
            .then(|| dockerfile_relpath(&s.dockerfile_path(), s.source_dir()));
        specs.push(TargetSpec {
            name: name.clone(),
            kind: TargetKind::Server,
            source_subdir: s.source_dir().to_string(),
            language: s.language.clone(),
            builder,
            dockerfile,
        });
    }
    // Deterministic order regardless of HashMap iteration.
    specs.sort_by(|a, b| (kind_name(a.kind), &a.name).cmp(&(kind_name(b.kind), &b.name)));
    specs
}

/// The Dockerfile path RELATIVE to the build VM's `/src` (which is mounted from the
/// server's `source_dir`). `dockerfile_path` is relative to the project root, so we
/// strip the `source_dir` prefix. Both are normalised (leading `./` removed). When
/// the Dockerfile isn't under `source_dir` (a misconfig), the path is returned
/// unchanged and the in-VM buildpack surfaces a clear "Dockerfile not found" error.
fn dockerfile_relpath(dockerfile_path: &str, source_dir: &str) -> String {
    let df = dockerfile_path.trim_start_matches("./");
    let sd = source_dir.trim_start_matches("./").trim_end_matches('/');
    if sd.is_empty() || sd == "." {
        return df.to_string();
    }
    df.strip_prefix(sd)
        .map(|r| r.trim_start_matches('/'))
        .unwrap_or(df)
        .to_string()
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
        // Buildpack (auto) servers carry no dockerfile.
        assert_eq!(specs[2].builder, Builder::Auto);
        assert!(specs[2].dockerfile.is_none());
    }

    #[test]
    fn enumerate_dockerfile_server_carries_relpath_and_builder() {
        // builder = "dockerfile" with the Dockerfile under the source dir → the
        // TargetSpec carries Builder::Dockerfile and the /src-relative path.
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\ndockerfile = \"./api/Dockerfile\"\nport = 3000\n",
        )
        .unwrap();
        let specs = enumerate_targets(&cfg);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].builder, Builder::Dockerfile);
        assert_eq!(specs[0].source_subdir, "./api"); // /src = ./api
        assert_eq!(specs[0].dockerfile.as_deref(), Some("Dockerfile")); // relative to /src

        // Explicit source + nested dockerfile → relpath strips the source prefix.
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\nsource = \".\"\ndockerfile = \"docker/api.Dockerfile\"\nport = 3000\n",
        )
        .unwrap();
        let specs = enumerate_targets(&cfg);
        assert_eq!(specs[0].dockerfile.as_deref(), Some("docker/api.Dockerfile"));
    }

    #[test]
    fn proxy_url_selects_public_any_only_for_dockerfile() {
        // With a distinct any-port, dockerfile builds get it; others get the narrow proxy.
        let net = BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, Some(3129), 100_000, 8);
        assert_eq!(net.proxy_url_for(false), "http://172.31.0.1:3128");
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3129");
        assert_eq!(net.proxy_any_port, Some(3129));

        // any-port == proxy_port disables the second proxy (dockerfile shares narrow).
        let net = BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, Some(3128), 100_000, 8);
        assert_eq!(net.proxy_any_port, None);
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3128");

        // No any-port → dockerfile falls back to the narrow proxy.
        let net = BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, None, 100_000, 8);
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3128");
    }

    #[test]
    fn per_lease_any_egress_rule_is_source_scoped() {
        // The per-lease grant pins BOTH the source guest IP and the gateway:port, so
        // it admits exactly one VM to the public-any proxy — and `-C` without `-s`
        // (verify_firewall's blanket-rule check) cannot match it.
        let net = BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, Some(3129), 100_000, 8);
        assert_eq!(
            net.any_egress_rule("172.31.0.5", 3129),
            vec![
                "-s", "172.31.0.5", "-p", "tcp", "-d", "172.31.0.1", "--dport", "3129",
                "-j", "ACCEPT",
            ]
        );
    }

    #[test]
    fn dockerfile_relpath_strips_source_prefix() {
        assert_eq!(dockerfile_relpath("./api/Dockerfile", "./api"), "Dockerfile");
        assert_eq!(dockerfile_relpath("Dockerfile", "."), "Dockerfile");
        assert_eq!(dockerfile_relpath("docker/Dockerfile", "."), "docker/Dockerfile");
        assert_eq!(dockerfile_relpath("svc/sub/Dockerfile", "svc"), "sub/Dockerfile");
        // Dockerfile not under the source dir (misconfig) → returned unchanged.
        assert_eq!(dockerfile_relpath("other/Dockerfile", "svc"), "other/Dockerfile");
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
        // The collision fix: a Rust *function* must NOT pick the server `rust.ext4` — the
        // language hint is ignored for the function kind (one per-kind image).
        assert_eq!(
            toolchain_candidates("function", Some("rust")),
            ["jkbuild-function.ext4", "function.ext4", "default.ext4"]
                .map(String::from)
                .to_vec(),
            "a function must never select a per-language server toolchain"
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

        // A non-bun package.json sniffs as Node (npm/pnpm/yarn).
        std::fs::write(dir.join("package.json"), r#"{"name":"x"}"#).unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("node"));
        std::fs::remove_file(dir.join("package.json")).unwrap();

        // A Cargo.toml (no JS manifest) sniffs as Rust.
        std::fs::write(dir.join("Cargo.toml"), "[package]\nname=\"x\"\n").unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("rust"));
        std::fs::remove_file(dir.join("Cargo.toml")).unwrap();

        // A go.mod (no manifest above) sniffs as Go; it wins over a stray Python
        // manifest (the compiled language owns a polyglot tree).
        std::fs::write(dir.join("go.mod"), "module x\n").unwrap();
        std::fs::write(dir.join("requirements.txt"), "flask\n").unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("go"));
        std::fs::remove_file(dir.join("go.mod")).unwrap();

        // A Python manifest alone (no go.mod / JS / Cargo) sniffs as Python.
        assert_eq!(detect_language(&dir, None).as_deref(), Some("python"));
        std::fs::remove_file(dir.join("requirements.txt")).unwrap();
        std::fs::write(dir.join("pyproject.toml"), "[project]\nname='x'\n").unwrap();
        assert_eq!(detect_language(&dir, None).as_deref(), Some("python"));

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
            cache_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            cache_size_bytes: 512 * 1024 * 1024,
            agent_bin: None,
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

        let net = Arc::new(BuildNet::new(
            "jkbuild0".into(),
            "172.31.0.1".into(),
            3128,
            None,
            100_000,
            8,
        ));
        let lease = net.acquire(false).await.expect("acquire build net");
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
            export_layered: false,
            build_function: false,
            builder_hint: None,
            dockerfile: None,
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
        let Some(fx) = bun_pipeline_build("bunfix", 1, Workload::OfflineNoDep).await else { return };
        let staged = &fx.staged;
        let store = &fx.store;
        let (project_id, build_id) = ("bunfix", 1u64);

        // Layered server artifact assembled into the deploy shape: NO flat tarball;
        // instead a content-addressed app erofs blob under _layers/.
        assert!(!staged.join("_servers/api.tar.gz").exists(), "no flat tarball in layered mode");

        // Manifest = jkbuild launch contract + jkbase.toml port + the layer refs the
        // host deploy path needs (app_layer filename + runtime language).
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
        assert_eq!(mani["runtime"], "bun", "runtime language recorded for host injection");
        let app_layer = mani["app_layer"].as_str().expect("app_layer recorded");
        assert!(
            app_layer.starts_with("sha256-") && app_layer.ends_with(".erofs"),
            "app_layer is a content-addressed erofs blob name: {app_layer}"
        );
        // The dumped + sha256-verified app blob is staged under _layers/.
        assert!(staged.join("_layers").join(app_layer).exists(), "app erofs blob staged");
        assert_eq!(
            mani["app_digest"].as_str().map(|d| d.replace("sha256:", "sha256-") + ".erofs").as_deref(),
            Some(app_layer),
            "app_digest matches the blob filename"
        );

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

        let _ = std::fs::remove_dir_all(staged);
        println!("PASS: run_project_build drove bun.ext4 -> layered app erofs blob + launch manifest");
    }

    /// Everything the on-box pipeline tests share after a successful build.
    struct BuildFixture {
        data: PathBuf,
        fc_release: PathBuf,
        kernel: PathBuf,
        store: Store,
        staged: PathBuf,
    }

    /// Which fixture + network wiring `bun_pipeline_build` drives.
    #[derive(Clone, Copy, PartialEq, Eq)]
    enum Workload {
        /// No deps, no build script — the offline rung (no bridge/proxy/seal).
        OfflineNoDep,
        /// Workspace monorepo with transitive deps + a dev dep to prune (fetch-then-seal).
        NetworkedMonorepo,
        /// A Solid/Vite app whose `bun run build` (`vite build`) only resolves
        /// solid-refresh's babel plugin when the toolchain ships real `node` — the
        /// regression guard for the bun-runtime resolver bug (`Cannot find module
        /// '../dist/babel.cjs'`). `bun run build` delegates vite's node-shebang bin to
        /// node when node is on PATH; without node it runs vite on bun's engine + fails.
        NetworkedSolidVite,
    }
    impl Workload {
        fn networked(self) -> bool {
            !matches!(self, Workload::OfflineNoDep)
        }
    }

    /// Shared build half: resolve the env, write a fixture, and drive it through
    /// `run_project_build`. Networked workloads wire the isolated build network +
    /// egress proxy so `bun install` must fetch through the proxy (fetch-then-seal).
    /// Returns `None` (with an explanatory eprintln) when the env isn't provisioned.
    async fn bun_pipeline_build(
        project_id: &str,
        build_id: u64,
        workload: Workload,
    ) -> Option<BuildFixture> {
        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return None;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return None;
        };
        let toolchain_dir = data.join("toolchains");
        if !toolchain_dir.join("bun.ext4").exists() {
            eprintln!("skip: {}/bun.ext4 not baked", toolchain_dir.display());
            return None;
        }
        // Layered runtime needs the 6.12 LTS kernel (erofs/overlay/pivot_root).
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        };

        // Fixture: a single Bun server, no Dockerfile, no deps. `language="bun"`
        // is the authoritative detect hint (forwarded as `jkbase.lang=bun`).
        let src = data.join(format!("bun-fixture-src-{project_id}"));
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
[routes."/"]
service = "server"
name = "api"
"#,
        );
        // Per-workload fixture under `server/` (all are a single `[servers.api]`,
        // language=bun; they differ in what the build must do):
        match workload {
            // Offline rung: a plain no-dep Bun server, no build script.
            Workload::OfflineNoDep => {
                write(
                    src.join("server/server.ts"),
                    "const port = Number(process.env.PORT) || 3000;\nBun.serve({ port, fetch() { return new Response(\"ok\\n\"); } });\nconsole.log(\"listening on \" + port);\n",
                );
                write(
                    src.join("server/package.json"),
                    "{\n  \"name\": \"bunfix\",\n  \"module\": \"server.ts\",\n  \"packageManager\": \"bun@1.3.14\",\n  \"scripts\": { \"start\": \"bun run server.ts\" }\n}\n",
                );
            }
            // A WORKSPACE monorepo (root `workspaces` + a member) with a real transitive
            // dep tree (debug → ms) AND root devDeps (typescript) — the exact shape that
            // broke the production-prune staging (`Workspace not found`). The server
            // imports ms+debug at runtime so a 200 proves the tree installed through the
            // proxy and runs; the prune must drop typescript from the app layer.
            Workload::NetworkedMonorepo => {
                write(
                    src.join("server/server.ts"),
                    "import ms from \"ms\";\nimport createDebug from \"debug\";\nconst log = createDebug(\"app\");\nconst port = Number(process.env.PORT) || 3000;\nBun.serve({ port, fetch() { log(\"req\"); return new Response(\"ok \" + ms(60000) + \"\\n\"); } });\nconsole.log(\"listening on \" + port);\n",
                );
                write(
                    src.join("server/package.json"),
                    "{\n  \"name\": \"bunfix\",\n  \"module\": \"server.ts\",\n  \"packageManager\": \"bun@1.3.14\",\n  \"workspaces\": [\"packages/*\"],\n  \"dependencies\": { \"ms\": \"^2.1.3\", \"debug\": \"^4.3.4\" },\n  \"devDependencies\": { \"typescript\": \"^5.6.0\" },\n  \"scripts\": { \"start\": \"bun run server.ts\" }\n}\n",
                );
                // A trivial workspace member so the root manifest's `workspaces` glob
                // resolves — the production-prune staging must handle this in-place.
                write(
                    src.join("server/packages/lib/package.json"),
                    "{ \"name\": \"@bunfix/lib\", \"version\": \"1.0.0\" }\n",
                );
            }
            // A minimal Solid SPA: `solid()` in the vite config STATICALLY imports
            // `solid-refresh/babel` at plugin-load (every build, dev or prod), so even
            // this trivial `vite build` trips bun's resolver bug UNLESS real `node` runs
            // vite. `bun run build` honours vite's `#!/usr/bin/env node` shebang and
            // delegates to the toolchain node; the build then completes fully offline
            // (post-seal). Asserted by `assert_app_layer_has_dist`.
            Workload::NetworkedSolidVite => {
                write(
                    src.join("server/package.json"),
                    "{\n  \"name\": \"solidfix\",\n  \"private\": true,\n  \"type\": \"module\",\n  \"packageManager\": \"bun@1.3.14\",\n  \"dependencies\": { \"solid-js\": \"^1.9.4\" },\n  \"devDependencies\": { \"vite\": \"^6.0.11\", \"vite-plugin-solid\": \"^2.11.1\" },\n  \"scripts\": { \"build\": \"vite build\", \"start\": \"bun run server.ts\" }\n}\n",
                );
                write(
                    src.join("server/vite.config.ts"),
                    "import solid from \"vite-plugin-solid\";\nimport { defineConfig } from \"vite\";\nexport default defineConfig({ plugins: [solid()] });\n",
                );
                write(
                    src.join("server/index.html"),
                    "<!doctype html>\n<html><head><meta charset=\"utf-8\"><title>solidfix</title></head>\n<body><div id=\"root\"></div><script type=\"module\" src=\"/src/index.tsx\"></script></body></html>\n",
                );
                write(
                    src.join("server/src/index.tsx"),
                    "import { render } from \"solid-js/web\";\nfunction App() {\n  return <div>hello solid</div>;\n}\nconst root = document.getElementById(\"root\");\nif (root) render(() => <App />, root);\n",
                );
                write(
                    src.join("server/server.ts"),
                    "const port = Number(process.env.PORT) || 3000;\nBun.serve({ port, fetch() { return new Response(\"ok\\n\"); } });\nconsole.log(\"listening on \" + port);\n",
                );
            }
        }

        let mut tarbuf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarbuf, flate2::Compression::fast());
            let mut tb = tar::Builder::new(enc);
            tb.append_dir_all(".", &src).unwrap();
            tb.into_inner().unwrap().finish().unwrap();
        }

        let store = Store::open(&data.join("onbox-bun.redb")).unwrap();
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

        // Networked builds need the isolated build bridge + the egress proxy: build
        // VMs can reach ONLY 172.31.0.1:3128 (JKBUILD firewall). The orchestrator
        // leases a TAP off `net` and wires the proxy + seal per target. Provision
        // first: sudo tools/setup-build-net.sh.
        let net = if workload.networked() {
            match tokio::net::TcpListener::bind("172.31.0.1:3128").await {
                Ok(listener) => {
                    tokio::spawn(crate::egress::serve(
                        listener,
                        Arc::new(crate::egress::EgressConfig::with_default_allowlist()),
                    ));
                    Some(Arc::new(BuildNet::new(
                        "jkbuild0".into(),
                        "172.31.0.1".into(),
                        3128,
                        None,
                        100_000,
                        8,
                    )))
                }
                Err(e) => {
                    eprintln!("skip: cannot bind egress proxy 172.31.0.1:3128 ({e}); run `sudo tools/setup-build-net.sh`");
                    return None;
                }
            }
        } else {
            None
        };

        let deps = Arc::new(BuildDeps {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel.clone(),
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
            net,
            // Real `bun install` over the network needs more headroom than the
            // offline rung's compile; the seal fires on FETCH-COMPLETE before this.
            fetch_deadline: Duration::from_secs(if workload.networked() { 180 } else { 120 }),
            cache_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            cache_size_bytes: 1024 * 1024 * 1024,
            agent_bin: None,
        });
        std::fs::create_dir_all(&deps.chroot_base).unwrap();

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone())
            .await
            .expect("bun server build should succeed");

        Some(BuildFixture { data, fc_release, kernel, store, staged })
    }

    /// Per-language build VM tuning (cargo wants more than `npm install`).
    struct BuildTuning {
        vcpu: u32,
        guest_mem_mib: u32,
        cgroup_mem_mib: u64,
        cgroup_cpu_max: &'static str,
        scratch_mib: u64,
        output_mib: u64,
        timeout_secs: u64,
        fetch_deadline_secs: u64,
    }

    /// Generic NETWORKED pipeline build for the language buildpacks: tar `src`, run
    /// it through the real `run_project_build` with the isolated build bridge + egress
    /// proxy (so the buildpack must fetch deps through the proxy, fetch-then-seal),
    /// and return the staged deployment. The source's `jkbase.toml` `language=` picks
    /// `toolchain` via select_toolchain. Mirrors `bun_pipeline_build`'s networked arm.
    async fn networked_lang_build(
        project_id: &str,
        redb: &str,
        toolchain: &str,
        src: &Path,
        t: BuildTuning,
        build_id: u64,
    ) -> Option<BuildFixture> {
        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return None;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return None;
        };
        let toolchain_dir = data.join("toolchains");
        if !toolchain_dir.join(toolchain).exists() {
            eprintln!("skip: {}/{toolchain} not baked", toolchain_dir.display());
            return None;
        }
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        };

        let mut tarbuf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarbuf, flate2::Compression::fast());
            let mut tb = tar::Builder::new(enc);
            tb.append_dir_all(".", src).unwrap();
            tb.into_inner().unwrap().finish().unwrap();
        }

        let store = Store::open(&data.join(redb)).unwrap();
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

        let net = match tokio::net::TcpListener::bind("172.31.0.1:3128").await {
            Ok(listener) => {
                tokio::spawn(crate::egress::serve(
                    listener,
                    Arc::new(crate::egress::EgressConfig::with_default_allowlist()),
                ));
                Some(Arc::new(BuildNet::new(
                    "jkbuild0".into(),
                    "172.31.0.1".into(),
                    3128,
                    None,
                    100_000,
                    8,
                )))
            }
            Err(e) => {
                eprintln!("skip: cannot bind egress proxy 172.31.0.1:3128 ({e}); run `sudo tools/setup-build-net.sh`");
                return None;
            }
        };

        let deps = Arc::new(BuildDeps {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel.clone(),
            data_dir: data.clone(),
            deploy_dir: data.join("hosting"),
            toolchain_dir,
            store: store.clone(),
            chroot_base: data.join(format!("bj-{project_id}")),
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            parent_cgroup: "jkbase-build".into(),
            uid: 100_000,
            gid: 100_000,
            timeout: Duration::from_secs(t.timeout_secs),
            vcpu_count: t.vcpu,
            mem_size_mib: t.guest_mem_mib,
            cgroup_pids_max: 1024,
            cgroup_mem_max_bytes: t.cgroup_mem_mib * 1024 * 1024,
            cgroup_cpu_max: t.cgroup_cpu_max.into(),
            scratch_size_bytes: t.scratch_mib * 1024 * 1024,
            output_size_bytes: t.output_mib * 1024 * 1024,
            console_log_max_bytes: 1024 * 1024,
            max_concurrent: 1,
            net,
            fetch_deadline: Duration::from_secs(t.fetch_deadline_secs),
            cache_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            cache_size_bytes: 1024 * 1024 * 1024,
            agent_bin: None,
        });
        std::fs::create_dir_all(&deps.chroot_base).unwrap();

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone())
            .await
            .expect("language server build should succeed");

        Some(BuildFixture { data, fc_release, kernel, store, staged })
    }

    /// Write the shared single-`api`-server jkbase.toml the boot helper expects
    /// (it asserts a layered `api` server + routes `/`). `language` selects the
    /// toolchain + the stamped runtime layer.
    fn write_lang_manifest(src: &Path, name: &str, language: &str) {
        write(
            src.join("jkbase.toml"),
            &format!(
                "[project]\nname = \"{name}\"\n\n[servers.api]\nsource = \"./server\"\nlanguage = \"{language}\"\nport = 3000\n\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n"
            ),
        );
    }

    /// Build a tiny Express (Node) app through the pipeline: `npm install express`
    /// MUST fetch through the proxy, then the node runtime layer serves it.
    async fn node_express_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("node-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "nodefix", "node");
        write(
            src.join("server/package.json"),
            "{\n  \"name\": \"nodefix\",\n  \"private\": true,\n  \"dependencies\": { \"express\": \"^4.21.0\" },\n  \"scripts\": { \"start\": \"node server.js\" }\n}\n",
        );
        write(
            src.join("server/server.js"),
            "const express = require(\"express\");\nconst app = express();\nconst port = Number(process.env.PORT) || 3000;\napp.get(\"/\", (_req, res) => res.send(\"ok\\n\"));\napp.listen(port, () => console.log(\"listening on \" + port));\n",
        );
        networked_lang_build(
            "nodefix",
            "onbox-node.redb",
            "node.ext4",
            &src,
            BuildTuning {
                vcpu: 2,
                guest_mem_mib: 1024,
                cgroup_mem_mib: 1536,
                cgroup_cpu_max: "200000 100000",
                scratch_mib: 512,
                output_mib: 64,
                timeout_secs: 180,
                fetch_deadline_secs: 180,
            },
            build_id,
        )
        .await
    }

    /// Build a tiny tiny_http (Rust) app through the pipeline: `cargo fetch` MUST
    /// pull tiny_http + deps through the proxy, the offline release build links
    /// glibc(base)+libgcc_s(rust runtime), and the layered runtime serves it.
    async fn rust_tiny_http_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("rust-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "rustfix", "rust");
        write(
            src.join("server/Cargo.toml"),
            "[package]\nname = \"rustfix\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntiny_http = \"0.12\"\n",
        );
        write(
            src.join("server/src/main.rs"),
            "fn main() {\n    let port: u16 = std::env::var(\"PORT\").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);\n    let server = tiny_http::Server::http((\"0.0.0.0\", port)).unwrap();\n    println!(\"listening on {port}\");\n    for req in server.incoming_requests() {\n        let _ = req.respond(tiny_http::Response::from_string(\"ok\\n\"));\n    }\n}\n",
        );
        networked_lang_build(
            "rustfix",
            "onbox-rust.redb",
            "rust.ext4",
            &src,
            BuildTuning {
                vcpu: 4,
                guest_mem_mib: 2048,
                cgroup_mem_mib: 2560,
                cgroup_cpu_max: "400000 100000",
                // cargo release build of tiny_http + deps writes a big target/ dir.
                scratch_mib: 2048,
                output_mib: 128,
                timeout_secs: 600,
                fetch_deadline_secs: 240,
            },
            build_id,
        )
        .await
    }

    /// Node acceptance: build → layered collection → metadata image → real agent
    /// runtime (node runtime layer over base) → HTTP 200. Same env as the bun
    /// pipeline test PLUS the `node.ext4` toolchain + the `node` runtime layer in
    /// the baselayers store, and the provisioned build bridge (express is fetched).
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once: jkbuild0 + firewall
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture node_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "node pipeline: needs KVM + root + node.ext4 + node runtime layer + agent + build bridge"]
    async fn node_pipeline_to_http_200() {
        let Some(fx) = node_express_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "nodep", "172.27.0.1", "172.27.0.2", "AA:FC:00:00:27:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered express/node server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: node(express) build -> layered collection -> node runtime layer -> HTTP 200 ({body:?})");
    }

    /// Rust acceptance: build → layered collection → metadata image → real agent
    /// runtime (rust runtime layer = libgcc_s, over base = glibc) → HTTP 200. Proves
    /// `cargo fetch` through the proxy, the glibc-dynamic binary, and that
    /// app:rust-runtime:base composes + serves.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture rust_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "rust pipeline: needs KVM + root + rust.ext4 + rust runtime layer + agent + build bridge"]
    async fn rust_pipeline_to_http_200() {
        let Some(fx) = rust_tiny_http_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "rustp", "172.26.0.1", "172.26.0.2", "AA:FC:00:00:26:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered tiny_http/rust server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: rust(tiny_http) build -> layered collection -> rust runtime layer -> HTTP 200 ({body:?})");
    }

    /// Build a tiny Python app through the pipeline: `pip install` MUST fetch the dep
    /// through the proxy into `.jkbase-deps`, then the python runtime layer imports it
    /// (PYTHONPATH=/app/.jkbase-deps) and serves. The server imports `six` (a vendored
    /// dep) AND serves "ok"; if pip didn't vendor it or PYTHONPATH is wrong, the import
    /// fails and there is no 200 — so a clean body proves the full fetch→vendor→import
    /// path.
    async fn python_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("python-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "pyfix", "python");
        write(src.join("server/requirements.txt"), "six==1.16.0\n");
        write(
            src.join("server/server.py"),
            "import os, six  # six is a vendored dep — import proves PYTHONPATH + pip\nfrom http.server import BaseHTTPRequestHandler, HTTPServer\nport = int(os.environ.get(\"PORT\", \"3000\"))\nassert six.PY3\nclass H(BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200); self.end_headers(); self.wfile.write(b\"ok\\n\")\n    def log_message(self, *a):\n        pass\nprint(\"listening on\", port)\nHTTPServer((\"0.0.0.0\", port), H).serve_forever()\n",
        );
        networked_lang_build(
            "pyfix",
            "onbox-python.redb",
            "python.ext4",
            &src,
            BuildTuning {
                vcpu: 2,
                guest_mem_mib: 1024,
                cgroup_mem_mib: 1536,
                cgroup_cpu_max: "200000 100000",
                scratch_mib: 768,
                output_mib: 128,
                timeout_secs: 240,
                fetch_deadline_secs: 180,
            },
            build_id,
        )
        .await
    }

    /// Build a tiny Go app through the pipeline: `go mod download` MUST pull a module
    /// through the proxy (proxy.golang.org / sum.golang.org allowlisted), the offline
    /// `CGO_ENABLED=0` build links a static binary, and the near-empty go runtime layer
    /// over base serves it. The app uses `github.com/google/uuid` (a fetched dep) +
    /// net/http, so a 200 proves the module fetch + static build + runtime compose.
    async fn go_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("go-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "gofix", "go");
        write(
            src.join("server/go.mod"),
            "module gofix\n\ngo 1.22\n\nrequire github.com/google/uuid v1.6.0\n",
        );
        write(
            src.join("server/main.go"),
            "package main\n\nimport (\n\t\"fmt\"\n\t\"net/http\"\n\t\"os\"\n\n\t\"github.com/google/uuid\"\n)\n\nfunc main() {\n\t_ = uuid.New() // exercise the fetched dep\n\tport := os.Getenv(\"PORT\")\n\tif port == \"\" {\n\t\tport = \"3000\"\n\t}\n\thttp.HandleFunc(\"/\", func(w http.ResponseWriter, r *http.Request) {\n\t\tfmt.Fprintln(w, \"ok\")\n\t})\n\tfmt.Println(\"listening on\", port)\n\thttp.ListenAndServe(\"0.0.0.0:\"+port, nil)\n}\n",
        );
        networked_lang_build(
            "gofix",
            "onbox-go.redb",
            "go.ext4",
            &src,
            BuildTuning {
                vcpu: 4,
                guest_mem_mib: 2048,
                cgroup_mem_mib: 2560,
                cgroup_cpu_max: "400000 100000",
                scratch_mib: 1536,
                output_mib: 128,
                timeout_secs: 600,
                fetch_deadline_secs: 240,
            },
            build_id,
        )
        .await
    }

    /// Python acceptance: build → layered collection → metadata image → real agent
    /// runtime (python runtime layer = CPython, over base = glibc) → HTTP 200. Needs
    /// `python.ext4` + the `python` runtime layer in the baselayers store.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture python_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "python pipeline: needs KVM + root + python.ext4 + python runtime layer + agent + build bridge"]
    async fn python_pipeline_to_http_200() {
        let Some(fx) = python_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "pyp", "172.25.0.1", "172.25.0.2", "AA:FC:00:00:25:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered python server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: python(pip+six) build -> layered collection -> python runtime layer -> HTTP 200 ({body:?})");
    }

    /// Go acceptance: build → layered collection → metadata image → real agent runtime
    /// (near-empty go runtime layer over base) → HTTP 200. Proves `go mod download`
    /// through the proxy, the CGO_ENABLED=0 static binary, and that app:go-runtime:base
    /// composes + serves. Needs `go.ext4` + the `go` runtime layer in the baselayers
    /// store.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture go_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "go pipeline: needs KVM + root + go.ext4 + go runtime layer + agent + build bridge"]
    async fn go_pipeline_to_http_200() {
        let Some(fx) = go_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "gop", "172.24.0.1", "172.24.0.2", "AA:FC:00:00:24:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered go server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: go(static+uuid) build -> layered collection -> go runtime layer -> HTTP 200 ({body:?})");
    }

    /// Build a Rust app that ships a DATA ASSET + an ENTRYPOINT script (the
    /// real-world shape the buildpack must support — e.g. an app baking ML models /
    /// seed data and seeding a volume on first boot). The binary reads
    /// `/app/data/greeting.txt` (only present if the buildpack ships assets) + the
    /// `SEED_MARKER` env (only set if the entrypoint ran), so a correct body proves
    /// BOTH the asset shipped AND `command = ["/bin/sh", "/app/entrypoint.sh"]` ran
    /// and exec'd the binary.
    async fn rust_assets_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("rust-assets-src");
        let _ = std::fs::remove_dir_all(&src);
        write(
            src.join("jkbase.toml"),
            "[project]\nname = \"rustassets\"\n\n[servers.api]\nsource = \"./server\"\nlanguage = \"rust\"\nport = 3000\ncommand = [\"/bin/sh\", \"/app/entrypoint.sh\"]\n\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n",
        );
        write(
            src.join("server/Cargo.toml"),
            "[package]\nname = \"assetfix\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntiny_http = \"0.12\"\n",
        );
        write(
            src.join("server/src/main.rs"),
            "fn main() {\n    let port: u16 = std::env::var(\"PORT\").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);\n    let greeting = std::fs::read_to_string(\"/app/data/greeting.txt\").unwrap_or_else(|_| \"MISSING\".into());\n    let marker = std::env::var(\"SEED_MARKER\").unwrap_or_else(|_| \"NOENV\".into());\n    let body = format!(\"{}-{}\\n\", greeting.trim(), marker);\n    let server = tiny_http::Server::http((\"0.0.0.0\", port)).unwrap();\n    println!(\"listening on {port}\");\n    for req in server.incoming_requests() {\n        let _ = req.respond(tiny_http::Response::from_string(body.clone()));\n    }\n}\n",
        );
        // The baked asset the binary reads at runtime (only present if shipped).
        write(src.join("server/data/greeting.txt"), "asset-ok\n");
        // The entrypoint: seed env (a stand-in for the real seed-volume/export work),
        // then exec the binary. Ships as a normal file; run via `sh` (no +x needed).
        write(
            src.join("server/entrypoint.sh"),
            "#!/bin/sh\nexport SEED_MARKER=seeded\nexec /app/assetfix\n",
        );
        networked_lang_build(
            "rustassets",
            "onbox-rustassets.redb",
            "rust.ext4",
            &src,
            BuildTuning {
                vcpu: 4,
                guest_mem_mib: 2048,
                cgroup_mem_mib: 2560,
                cgroup_cpu_max: "400000 100000",
                scratch_mib: 2048,
                output_mib: 128,
                timeout_secs: 600,
                fetch_deadline_secs: 240,
            },
            build_id,
        )
        .await
    }

    /// Rust assets + entrypoint acceptance: build → ship the data asset + entrypoint
    /// into the app layer → runtime → the entrypoint runs, sets env, exec's the
    /// binary, which reads the baked asset → HTTP 200 "asset-ok-seeded". Proves the
    /// fix for the binary-only app layer (assets now ship) AND that a `command=`
    /// entrypoint can seed env + exec.
    ///
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture rust_assets_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "rust assets pipeline: needs KVM + root + rust.ext4 + rust runtime layer + agent + build bridge"]
    async fn rust_assets_pipeline_to_http_200() {
        let Some(fx) = rust_assets_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "rusta", "172.25.0.1", "172.25.0.2", "AA:FC:00:00:25:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the rust server reading a baked asset via its entrypoint");
        assert_eq!(body, "asset-ok-seeded", "asset must ship (asset-ok) AND entrypoint must run (seeded)");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: rust assets+entrypoint build -> app layer with assets -> entrypoint exec -> HTTP 200 ({body:?})");
    }

    /// Build a Rust app with a real NATIVE dynamic dependency (`openssl` →
    /// openssl-sys, system/dynamic → links `libssl.so.3`/`libcrypto.so.3`). The
    /// rust runtime layer + base ship NEITHER, so the only way this serves is if the
    /// buildpack shipped the binary's native-lib closure into the app layer's
    /// /usr/lib — the per-app fix for native FFI deps (vs polluting the shared layer).
    async fn rust_native_lib_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("rust-native-src");
        let _ = std::fs::remove_dir_all(&src);
        write_lang_manifest(&src, "rustnative", "rust");
        write(
            src.join("server/Cargo.toml"),
            "[package]\nname = \"rustnative\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ntiny_http = \"0.12\"\nopenssl = \"0.10\"\n",
        );
        // openssl::version::version() forces libssl/libcrypto to be LINKED and CALLED
        // at runtime — so a missing native-lib closure fails the binary on startup.
        write(
            src.join("server/src/main.rs"),
            "fn main() {\n    let port: u16 = std::env::var(\"PORT\").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);\n    let v = openssl::version::version();\n    let tag = v.split(' ').next().unwrap_or(\"?\");\n    let body = format!(\"native-ok {}\\n\", tag);\n    let server = tiny_http::Server::http((\"0.0.0.0\", port)).unwrap();\n    println!(\"listening on {port}\");\n    for req in server.incoming_requests() {\n        let _ = req.respond(tiny_http::Response::from_string(body.clone()));\n    }\n}\n",
        );
        networked_lang_build(
            "rustnative",
            "onbox-rustnative.redb",
            "rust.ext4",
            &src,
            BuildTuning {
                vcpu: 4,
                guest_mem_mib: 2048,
                cgroup_mem_mib: 2560,
                cgroup_cpu_max: "400000 100000",
                scratch_mib: 2048,
                output_mib: 128,
                timeout_secs: 600,
                fetch_deadline_secs: 240,
            },
            build_id,
        )
        .await
    }

    /// Native-FFI acceptance: a Rust app linking openssl (libssl/libcrypto) builds →
    /// the buildpack ships its native-lib closure into the app layer's /usr/lib →
    /// the layered runtime (whose rust runtime layer + base carry NO openssl) serves
    /// it → HTTP 200 "native-ok OpenSSL". Proves native deps ride the app layer, NOT
    /// the shared rust runtime layer.
    ///
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture rust_native_lib_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "rust native-lib pipeline: needs KVM + root + rust.ext4 + rust runtime layer + agent + build bridge"]
    async fn rust_native_lib_pipeline_to_http_200() {
        let Some(fx) = rust_native_lib_build(1).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "rustn", "172.24.0.1", "172.24.0.2", "AA:FC:00:00:24:02",
        )
        .await
        .expect("agent should serve HTTP 200 from a rust server linking openssl via the per-app native-lib closure");
        assert_eq!(body, "native-ok OpenSSL", "openssl (libssl/libcrypto) must be shipped into the app layer and resolve at runtime");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: rust native-FFI (openssl) build -> app-layer /usr/lib closure -> runtime -> HTTP 200 ({body:?})");
    }

    async fn sh(cmd: &str, args: &[&str]) -> std::io::Result<()> {
        let status = tokio::process::Command::new(cmd).args(args).status().await?;
        if !status.success() {
            return Err(std::io::Error::other(format!("{cmd} {args:?} failed ({status})")));
        }
        Ok(())
    }

    /// Poll a raw HTTP/1.0 GET until a 200, returning the trimmed body.
    async fn poll_http_200(ip: &str, port: u16, timeout: Duration) -> Option<String> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let deadline = std::time::Instant::now() + timeout;
        while std::time::Instant::now() < deadline {
            if let Ok(mut s) = tokio::net::TcpStream::connect((ip, port)).await {
                let _ = s.write_all(b"GET / HTTP/1.0\r\nHost: jkbase\r\n\r\n").await;
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() {
                    let text = String::from_utf8_lossy(&buf);
                    if let Some((head, body)) = text.split_once("\r\n\r\n")
                        && head.lines().next().is_some_and(|l| l.contains(" 200 "))
                    {
                        return Some(body.trim().to_string());
                    }
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        None
    }

    /// Resolve the runtime-boot env (baselayers store + musl agent) shared by the
    /// pipeline acceptance tests, or `None` (with a skip note) if unset.
    fn resolve_runtime_env(fx: &BuildFixture) -> Option<(PathBuf, PathBuf)> {
        let store_dir = std::env::var("JKB_BASELAYERS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| fx.data.join("baselayers"));
        if !store_dir.join("platform.json").exists() {
            eprintln!("skip: no baselayers store at {}", store_dir.display());
            return None;
        }
        let agent_bin = match std::env::var("JKB_AGENT").map(PathBuf::from) {
            Ok(p) if p.exists() => p,
            Ok(p) => {
                eprintln!("skip: agent binary {} missing", p.display());
                return None;
            }
            Err(_) => {
                eprintln!("skip: set JKB_AGENT to the musl jkbase-agent binary");
                return None;
            }
        };
        Some((store_dir, agent_bin))
    }

    /// Boot the real `jkbase-agent` runtime VM for `fx`'s built deployment over a
    /// point-to-point tap and return the body it serves at `/`. `tag` namespaces the
    /// on-disk artifacts + tap; the caller picks a subnet clear of jkbuild0 (172.31.x).
    #[allow(clippy::too_many_arguments)]
    async fn boot_layered_and_curl(
        fx: &BuildFixture,
        store_dir: &Path,
        agent_bin: &Path,
        tag: &str,
        host_ip: &str,
        guest_ip: &str,
        guest_mac: &str,
    ) -> Option<String> {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        // Host glue under test: resolve the layer plan + bake the metadata image,
        // treating the staged build as the deployment dir.
        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, store_dir, false, true)
            .expect("compute layer plan from the built deployment");
        assert!(!plan.layer_paths.is_empty(), "a layered server must resolve >=1 erofs layer");
        assert!(plan.runtime_layers.servers.contains_key("api"), "_layers.json maps the api server");

        let meta_img = fx.data.join(format!("{tag}-metadata.ext4"));
        crate::layer_plan::build_metadata_image(&fx.staged, &plan, &Default::default(), &meta_img)
            .expect("build the metadata image");

        // Agent base rootfs (vda). With JKB_ROOTFS set, boot the prebuilt apko rootfs
        // verbatim — it carries the agent as /sbin/init AND `veritysetup`, which the
        // dm-verity layers REQUIRE to activate in-guest (so the agent under test is the
        // one baked into that rootfs; JKB_AGENT is not injected in this mode). Otherwise
        // hand-roll a minimal static-agent rootfs with no userland — fine for plain
        // (non-verity) layers, but it cannot activate verity, so a verity'd store would
        // correctly fail closed under it.
        let rootfs_img = if let Ok(prebuilt) = std::env::var("JKB_ROOTFS") {
            let p = PathBuf::from(prebuilt);
            assert!(p.exists(), "JKB_ROOTFS {} missing", p.display());
            p
        } else {
            let rootfs_stage = fx.data.join(format!("{tag}-vda-stage"));
            let _ = std::fs::remove_dir_all(&rootfs_stage);
            for d in ["sbin", "proc", "sys", "dev", "tmp", "srv/www", "mnt/data"] {
                std::fs::create_dir_all(rootfs_stage.join(d)).unwrap();
            }
            std::fs::copy(agent_bin, rootfs_stage.join("sbin/init")).unwrap();
            {
                use std::os::unix::fs::PermissionsExt;
                let p = rootfs_stage.join("sbin/init");
                let mut perm = std::fs::metadata(&p).unwrap().permissions();
                perm.set_mode(0o755);
                std::fs::set_permissions(&p, perm).unwrap();
            }
            let rootfs_img = fx.data.join(format!("{tag}-vda.ext4"));
            jkbase_orch::build_image::build_ro_ext4_from_dir(&rootfs_stage, &rootfs_img, 48).unwrap();
            rootfs_img
        };

        // Point-to-point tap (clear of jkbuild0's 172.31.x).
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"]).await.unwrap();
        sh("ip", &["addr", "add", &format!("{host_ip}/24"), "dev", &tap]).await.unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs_img.clone(),
            metadata_image_path: Some(meta_img.clone()),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: None,
            vcpu_count: 2,
            mem_size_mib: 1024,
            tap_device: Some(tap.clone()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
        };
        let runtime_dir = fx.data.join(format!("{tag}-run"));
        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("runtime VM should start");

        let res = poll_http_200(guest_ip, 80, Duration::from_secs(45)).await;
        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;
        res
    }

    /// F — the WS4 acceptance demo: the **full pipeline** end to end. A real Bun
    /// server is built through `run_project_build` (→ a layered app erofs blob),
    /// the host resolves the layer plan + bakes the metadata image
    /// (`compute_layer_plan` + `build_metadata_image`), and the **real
    /// `jkbase-agent` runtime VM** boots with the metadata image + base/runtime/app
    /// erofs layers → the agent composes the per-server overlay + pivot_root → bun
    /// serves → HTTP 200. This is the first proof that the BUILT app layer (not a
    /// hand-rolled one) composes with the shared store layers and serves through the
    /// production runtime path.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/jkbob JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/.firecracker/baselayers \
    ///       JKB_AGENT=/abs/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    ///       <test-bin> --ignored --nocapture bun_layered_pipeline_to_http_200
    ///
    /// Needs everything `bun_server_build_through_orchestrator` needs, plus the
    /// populated baselayers store (`JKB_BASELAYERS`, default `$JKB_DATA/baselayers`)
    /// and the musl agent binary (`JKB_AGENT`). Uses a point-to-point tap
    /// (172.31.0.1/24), sidestepping the dev-box jkbr0 bridge quirk.
    #[tokio::test]
    #[ignore = "full pipeline: needs KVM + root + bun.ext4 + baselayers + musl agent"]
    async fn bun_layered_pipeline_to_http_200() {
        let Some(fx) = bun_pipeline_build("bunpipe", 1, Workload::OfflineNoDep).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "pipe", "172.30.0.1", "172.30.0.2", "AA:FC:00:00:30:02",
        )
        .await
        .expect("agent should proxy HTTP 200 from the layered bun server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: build -> layered collection -> metadata image -> real agent runtime -> HTTP 200 ({body:?})");
    }

    /// Networked — the real-dependency proof. A Bun server importing `ms` is built
    /// through `run_project_build` with the isolated build network + egress proxy, so
    /// `bun install` MUST fetch `ms` through the proxy (fetch-then-seal), then the
    /// layered runtime serves a response computed with `ms` → HTTP 200 "ok 1m". The
    /// 200 proves the dependency was fetched through the proxy AND the app runs with
    /// it. This is the gate before any non-trivial app can be deployed.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once: provision jkbuild0 + the firewall
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture bun_networked_pipeline_to_http_200
    ///
    /// Needs everything `bun_layered_pipeline_to_http_200` needs, PLUS outbound
    /// internet and the provisioned build bridge (`sudo tools/setup-build-net.sh`).
    #[tokio::test]
    #[ignore = "networked pipeline: + internet + provisioned build bridge (setup-build-net.sh)"]
    async fn bun_networked_pipeline_to_http_200() {
        let Some(fx) = bun_pipeline_build("bunnet", 1, Workload::NetworkedMonorepo).await else { return };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };

        // Lean-layer proof: the built app erofs carries the PRODUCTION deps (ms, debug)
        // but NOT the dev dep (typescript) — pruned out of the runtime layer.
        assert_app_layer_pruned(&fx.staged).await;

        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "netpipe", "172.28.0.1", "172.28.0.2", "AA:FC:00:00:28:02",
        )
        .await
        .expect("agent should serve 200 using the proxy-fetched `ms` dependency");
        assert_eq!(
            body, "ok 1m",
            "response uses ms(60000)=1m — proves `ms` was fetched through the egress proxy and runs"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: networked bun install (ms+debug via proxy, sealed) + lean prune (no typescript) -> layered runtime -> HTTP 200 ({body:?})");
    }

    /// Mount the staged app erofs layer and assert the lean prune kept production deps
    /// (ms, debug) and dropped the dev dep (typescript).
    async fn assert_app_layer_pruned(staged: &Path) {
        let layers_dir = staged.join("_layers");
        let app_erofs = std::fs::read_dir(&layers_dir)
            .expect("_layers dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "erofs"))
            .expect("app erofs layer present");
        let mnt = staged.join("_probe-mnt");
        let _ = std::fs::create_dir_all(&mnt);
        sh("mount", &["-t", "erofs", "-o", "ro,loop", app_erofs.to_str().unwrap(), mnt.to_str().unwrap()])
            .await
            .expect("mount app erofs");
        let nm = mnt.join("app/node_modules");
        let present = |p: &str| nm.join(p).exists();
        let (has_ms, has_debug, has_ts) = (present("ms"), present("debug"), present("typescript"));
        let _ = sh("umount", &[mnt.to_str().unwrap()]).await;
        let _ = std::fs::remove_dir_all(&mnt);
        assert!(has_ms, "production dep `ms` must be in the app layer");
        assert!(has_debug, "production dep `debug` must be in the app layer");
        assert!(!has_ts, "dev dep `typescript` must be PRUNED from the app layer");
    }

    /// Networked Solid/Vite regression guard. A minimal Solid SPA is built through
    /// `run_project_build`; its `bun run build` (`vite build`) loads `vite-plugin-solid`,
    /// which statically imports `solid-refresh/babel`. Under the BUN runtime that
    /// resolves to `Cannot find module '../dist/babel.cjs' from ''` (a bun resolver
    /// bug) — but `bun run build` delegates vite's `#!/usr/bin/env node` bin to real
    /// node when the toolchain (`bun.ext4`) ships it, so the build completes fully
    /// offline (post-seal). Without `node` in the toolchain this build FAILS — this is
    /// the guard against regressing the `nodejs` apk in build-bun.apko.yaml.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once: provision jkbuild0 + the firewall
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… \
    ///       <test-bin> --ignored --nocapture bun_networked_solid_vite_build
    ///
    /// Needs KVM + root + outbound internet + the provisioned build bridge. Build half
    /// only — no runtime boot, so baselayers/agent are not required.
    #[tokio::test]
    #[ignore = "networked: + internet + provisioned build bridge (setup-build-net.sh); regression guard — needs `node` in bun.ext4"]
    async fn bun_networked_solid_vite_build() {
        let Some(fx) = bun_pipeline_build("bunsolid", 1, Workload::NetworkedSolidVite).await else {
            return;
        };
        // `run_project_build` returning Ok already means `vite build` ran to completion
        // (a failed build bails the compile phase); this asserts the bundle physically
        // landed in the app layer.
        assert_app_layer_has_dist(&fx.staged).await;
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: networked Solid/Vite `bun run build` delegated to node -> dist/ in the app layer");
    }

    /// Mount the staged app erofs layer and assert the Vite build output landed at
    /// `app/dist/index.html` (proves `bun run build` produced a bundle, not just exit 0).
    async fn assert_app_layer_has_dist(staged: &Path) {
        let layers_dir = staged.join("_layers");
        let app_erofs = std::fs::read_dir(&layers_dir)
            .expect("_layers dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .find(|p| p.extension().is_some_and(|x| x == "erofs"))
            .expect("app erofs layer present");
        let mnt = staged.join("_probe-dist-mnt");
        let _ = std::fs::create_dir_all(&mnt);
        sh("mount", &["-t", "erofs", "-o", "ro,loop", app_erofs.to_str().unwrap(), mnt.to_str().unwrap()])
            .await
            .expect("mount app erofs");
        let has_dist = mnt.join("app/dist/index.html").exists();
        let _ = sh("umount", &[mnt.to_str().unwrap()]).await;
        let _ = std::fs::remove_dir_all(&mnt);
        assert!(
            has_dist,
            "vite build output app/dist/index.html must be in the app layer (proves `bun run build` ran under node)"
        );
    }

    /// Build a user Dockerfile SERVER-SIDE through `run_project_build` with the
    /// dockerfile toolchain + the isolated build net. The Dockerfile's `FROM`
    /// pulls through the 3129 PUBLIC-ANY proxy (Docker Hub is NOT on the
    /// allowlist), its `RUN` exercises crun, and buildah flattens the image into
    /// ONE self-contained `image/self` erofs layer. Returns the staged deployment.
    async fn dockerfile_pipeline_build(project_id: &str, build_id: u64) -> Option<BuildFixture> {
        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return None;
        };
        let Ok(fc_release) = std::env::var("JKB_FC_RELEASE").map(PathBuf::from) else {
            eprintln!("skip: set JKB_FC_RELEASE");
            return None;
        };
        let toolchain_dir = data.join("toolchains");
        if !toolchain_dir.join("dockerfile.ext4").exists() {
            eprintln!("skip: {}/dockerfile.ext4 not baked (run `tools/dev toolchains`)", toolchain_dir.display());
            return None;
        }
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        };

        // Fixture: ONE server built from a user Dockerfile. The image serves "ok" on
        // $PORT (the platform routing contract). builder="dockerfile" → image/self.
        let src = data.join(format!("df-fixture-src-{project_id}"));
        let _ = std::fs::remove_dir_all(&src);
        write(src.join("jkbase.toml"), "[project]\nname = \"dffix\"\n[servers.api]\nbuilder = \"dockerfile\"\ndockerfile = \"./svc/Dockerfile\"\nport = 8080\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n");
        // FROM (pull via 3129) + RUN (crun) + COPY + a relative CMD (resolved via the
        // image's own PATH — exercises the image/self non-clobbering env path).
        write(src.join("svc/Dockerfile"), "FROM python:3.12-alpine\nRUN echo built-in-vm > /built.txt\nCOPY server.py /server.py\nCMD [\"python3\", \"/server.py\"]\n");
        write(src.join("svc/server.py"), "import os, http.server, socketserver\nport = int(os.environ.get('PORT', '8080'))\nclass H(http.server.BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')\n    def log_message(self, *a):\n        pass\nsocketserver.TCPServer(('0.0.0.0', port), H).serve_forever()\n");

        let mut tarbuf = Vec::new();
        {
            let enc = flate2::write::GzEncoder::new(&mut tarbuf, flate2::Compression::fast());
            let mut tb = tar::Builder::new(enc);
            tb.append_dir_all(".", &src).unwrap();
            tb.into_inner().unwrap().finish().unwrap();
        }

        let store = Store::open(&data.join("onbox-df.redb")).unwrap();
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

        // Dockerfile FROM/RUN need broad egress → the 3129 PUBLIC-ANY proxy. Bind
        // BOTH 3128 (allowlist) + 3129 (allow_any); BuildNet with the any-port routes
        // the dockerfile target to 3129 (proxy_url_for). Requires `sudo tools/dev net`.
        let net = {
            let allow = match tokio::net::TcpListener::bind("172.31.0.1:3128").await {
                Ok(l) => l,
                Err(e) => { eprintln!("skip: cannot bind 172.31.0.1:3128 ({e}); run `sudo tools/dev net`"); return None; }
            };
            let any = match tokio::net::TcpListener::bind("172.31.0.1:3129").await {
                Ok(l) => l,
                Err(e) => { eprintln!("skip: cannot bind 172.31.0.1:3129 ({e}); run `sudo tools/dev net`"); return None; }
            };
            tokio::spawn(crate::egress::serve(allow, Arc::new(crate::egress::EgressConfig::with_default_allowlist())));
            tokio::spawn(crate::egress::serve(any, Arc::new(crate::egress::EgressConfig::allow_any_public())));
            Some(Arc::new(BuildNet::new("jkbuild0".into(), "172.31.0.1".into(), 3128, Some(3129), 100_000, 8)))
        };

        let deps = Arc::new(BuildDeps {
            jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel.clone(),
            data_dir: data.clone(),
            deploy_dir: data.join("hosting"),
            toolchain_dir,
            store: store.clone(),
            chroot_base: data.join("bj-df"),
            cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
            parent_cgroup: "jkbase-build".into(),
            uid: 100_000,
            gid: 100_000,
            timeout: Duration::from_secs(600),
            vcpu_count: 2,
            mem_size_mib: 2048, // buildah pull+flatten needs more than a thin bun build
            cgroup_pids_max: 1024,
            cgroup_mem_max_bytes: 2560 * 1024 * 1024,
            cgroup_cpu_max: "200000 100000".into(),
            // The orchestrator bumps these to the dockerfile floor (16 GiB / 6 GiB).
            scratch_size_bytes: 256 * 1024 * 1024,
            output_size_bytes: 64 * 1024 * 1024,
            console_log_max_bytes: 1024 * 1024,
            max_concurrent: 1,
            net,
            fetch_deadline: Duration::from_secs(300),
            cache_locks: Arc::new(tokio::sync::Mutex::new(std::collections::HashMap::new())),
            cache_size_bytes: 512 * 1024 * 1024,
            agent_bin: None,
        });
        std::fs::create_dir_all(&deps.chroot_base).unwrap();

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone())
            .await
            .expect("dockerfile server build should succeed");
        Some(BuildFixture { data, fc_release, kernel, store, staged })
    }

    /// Assert the dockerfile build produced exactly ONE app erofs layer and the
    /// server manifest is marked image/self (single-layer runtime, no base/runtime).
    async fn assert_image_self_single_layer(staged: &Path) {
        let layers: Vec<_> = std::fs::read_dir(staged.join("_layers"))
            .expect("_layers dir")
            .filter_map(|e| e.ok())
            .map(|e| e.path())
            .filter(|p| p.extension().is_some_and(|x| x == "erofs"))
            .collect();
        assert_eq!(layers.len(), 1, "a dockerfile build is ONE self-contained app layer");
        let mani: serde_json::Value =
            serde_json::from_slice(&std::fs::read(staged.join("_servers/api.json")).unwrap()).unwrap();
        assert_eq!(mani["runtime"], "image/self", "dockerfile server runtime must be image/self");
    }

    /// The dockerfile-builder acceptance proof: a user Dockerfile is built
    /// server-side (buildah `FROM` via the 3129 public-any proxy + a `RUN` via crun),
    /// flattened into ONE image/self erofs layer, and the layered runtime boots it as
    /// a single lowerdir (the image's own python entrypoint, resolved via the image's
    /// PATH) → HTTP 200. End-to-end proof of `builder = "dockerfile"` on B2.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/dev net   # jkbuild0 + firewall (3128+3129) + cgroup
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture dockerfile_pipeline_to_http_200
    ///
    /// Needs KVM + root + dockerfile.ext4 + baselayers + the musl agent + outbound
    /// internet + the provisioned build bridge (`sudo tools/dev net`).
    #[tokio::test]
    #[ignore = "dockerfile pipeline: KVM + root + dockerfile.ext4 + baselayers + agent + internet + `sudo tools/dev net`"]
    async fn dockerfile_pipeline_to_http_200() {
        let Some(fx) = dockerfile_pipeline_build("dfpipe", 1).await else { return };
        assert_image_self_single_layer(&fx.staged).await;
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else { return };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "dfpipe", "172.27.0.1", "172.27.0.2", "AA:FC:00:00:27:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the dockerfile-built image/self server");
        assert_eq!(body, "ok", "the image's own python entrypoint serves 'ok' on $PORT");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!("PASS: builder=dockerfile (buildah FROM via 3129 public-any + RUN via crun) -> single image/self erofs layer -> runtime -> HTTP 200 ({body:?})");
    }
}
