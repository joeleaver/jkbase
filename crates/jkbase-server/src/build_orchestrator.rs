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

use anyhow::{Context, Result, bail, ensure};
use jkbase_common::config::{Builder, EgressPolicy, ProjectConfig, resolve_egress};
use jkbase_control::store::{BuildPhase, BuildTargetStatus, Store, TargetKind};
use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig, SealFn, is_safe_cmdline_path};
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
            "link",
            "set",
            "dev",
            tap,
            "type",
            "bridge_slave",
            "isolated",
            "on",
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
        let input_hook = [
            "-w",
            "-C",
            "INPUT",
            "-i",
            self.bridge.as_str(),
            "-j",
            "JKBUILD",
        ];
        let fwd_drop = [
            "-w",
            "-C",
            "FORWARD",
            "-i",
            self.bridge.as_str(),
            "-j",
            "DROP",
        ];
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
                "-w",
                "-C",
                "JKBUILD",
                "-p",
                "tcp",
                "-d",
                self.gateway.as_str(),
                "--dport",
                &any.to_string(),
                "-j",
                "ACCEPT",
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
            "-w",
            "-C",
            "JKBUILD",
            "-p",
            "tcp",
            "-d",
            self.gateway.as_str(),
            "--dport",
            &self.proxy_port.to_string(),
            "-j",
            "ACCEPT",
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
                "-t",
                "filter",
                "-A",
                SOURCE_GUARD_CHAIN,
                "-i",
                tap.as_str(),
                "-p",
                "802_1Q",
                "-j",
                "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t",
                "filter",
                "-A",
                SOURCE_GUARD_CHAIN,
                "-i",
                tap.as_str(),
                "!",
                "-s",
                mac.as_str(),
                "-j",
                "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t",
                "filter",
                "-A",
                SOURCE_GUARD_CHAIN,
                "-i",
                tap.as_str(),
                "-p",
                "IPv4",
                "!",
                "--ip-src",
                ip.as_str(),
                "-j",
                "DROP",
            ])
            .await?;
            run_ebtables(&[
                "-t",
                "filter",
                "-A",
                SOURCE_GUARD_CHAIN,
                "-i",
                tap.as_str(),
                "-p",
                "ARP",
                "!",
                "--arp-ip-src",
                ip.as_str(),
                "-j",
                "DROP",
            ])
            .await?;
        }
        // Hook into the L2 INPUT (frames to the gateway/host) + FORWARD (VM↔VM, already
        // isolated — defense in depth) paths, once each. Rules match `-i jkbld*`, so
        // frames from the runtime bridge fall straight through with no effect.
        for hook in ["INPUT", "FORWARD"] {
            if !ebtables_ok(&["-t", "filter", "--check", hook, "-j", SOURCE_GUARD_CHAIN]).await {
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
    let cap = deps
        .store
        .get_quota(project_id)
        .ok()?
        .build_seconds_per_month;
    Some((used, cap))
}

async fn run_ip(args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new("ip")
        .args(args)
        .status()
        .await?;
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
    /// Build CONTEXT subdir, relative to the unpacked source root. This is the dir
    /// turned into the RO source image and mounted at `/src` in the build VM. It
    /// defaults to the target's `source` (see [`TargetSpec::build_subdir`]), so the
    /// no-`context` path is identical to today's "mount just the source subdir".
    /// When set wider than the source (e.g. a workspace root), an in-repo sibling
    /// path-dep is inside the mount and resolves.
    context_subdir: String,
    /// The target's `source` path interpreted RELATIVE TO `context_subdir` — i.e.
    /// WHERE, inside the mounted context, the build actually runs (detect + the
    /// buildpack `app_dir`). `"."` when `context` is unset (build at the context
    /// root), preserving today's behaviour.
    build_subdir: String,
    language: Option<String>,
    /// Build strategy (`auto` buildpack detect, or the `dockerfile` escape hatch).
    builder: Builder,
    /// Dockerfile path relative to `build_subdir` (i.e. relative to the buildpack's
    /// app_dir, `<context>/<build_subdir>` in the VM), for `builder = "dockerfile"`.
    /// `None` otherwise.
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
        // 4. Non-build artifacts: static site content FIRST, then the host-authored
        //    `_`-prefixed sidecars — so a host artifact is always written LAST and a tenant
        //    cannot clobber it via site content (defense-in-depth for B-1; copy_filtered_guarded
        //    already refuses `_`-prefixed top-level tenant entries into the root).
        assemble_sites(&config, &src_dir, &staged).context("assemble site content")?;
        assemble_sidecars(&config, &staged).context("assemble config sidecars")?;
        std::fs::create_dir_all(staged.join("_functions"))?;
        std::fs::create_dir_all(staged.join("_servers"))?;
        // Managed DB: stage the schema (+ optional rules) from the source tree into a
        // host-namespaced `_database/` dir with FIXED dest names (the tenant can't pick
        // them). Paths were traversal-guarded in validate_manifest; a missing file fails
        // the deploy here (the source-tree existence check). Both ride into the metadata
        // image and drive the agent's rhypedb supervisor.
        if let Some(db) = config.database.as_ref() {
            let dbdir = staged.join("_database");
            std::fs::create_dir_all(&dbdir)?;
            stage_db_file(&src_dir, &db.schema, &dbdir.join("schema.rhype"))?;
            if let Some(rules) = db.rules.as_deref() {
                stage_db_file(&src_dir, rules, &dbdir.join("rules.rhype"))?;
            }
        }

        // 5. Enumerate per-target build work.
        let specs = enumerate_targets(&config);
        if specs.is_empty() {
            info!(
                project_id,
                build_id, "no build targets; static/site-only deploy"
            );
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
                    &spec,
                    &config,
                    &deps,
                    &src_dir,
                    &workspace,
                    &staged,
                    &project_id,
                    build_id,
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

    // The CONTEXT dir is what becomes the RO image and is mounted at /src; the build
    // runs in `build_subdir` WITHIN it. With `context` unset, `context_subdir` is the
    // source and `build_subdir` is "." — identical to the historical single-subdir mount.
    let context_path = src_dir.join(&spec.context_subdir);
    if !context_path.is_dir() {
        bail!(
            "build context dir '{}' not found for target '{}'",
            spec.context_subdir,
            spec.name
        );
    }
    // Where the build actually runs inside the context (detect + buildpack app_dir).
    let build_path = context_path.join(&spec.build_subdir);
    if !build_path.is_dir() {
        bail!(
            "source dir '{}' (within build context '{}') not found for target '{}'",
            spec.build_subdir,
            spec.context_subdir,
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
        // sniff of the build subdir (the in-VM lifecycle does the authoritative detect).
        let l = detect_language(&build_path, spec.language.as_deref());
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

    // RO source drive built from the CONTEXT subdir in userspace — no mount (P0-3).
    // With a wider context this mounts the whole context (e.g. a workspace root) so
    // sibling path-deps are present; the build still runs in `build_subdir` within it.
    build_ro_ext4_from_dir(&context_path, &source_img, 16)
        .with_context(|| format!("build source image for '{}'", spec.name))?;

    // Keep the VM id short: it becomes the jailer chroot path, and the Firecracker
    // API Unix socket under it must stay within SUN_LEN (~108 bytes). Checked
    // BEFORE leasing a TAP, so a too-long path bails without leaking a net slot.
    let kind_char = match spec.kind {
        TargetKind::Function => 'f',
        TargetKind::Server => 's',
        TargetKind::Static => 't',
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
        fsize_limit_bytes: Some(scratch_size_bytes.max(output_size_bytes).max(
            if cache_drive.is_some() {
                deps.cache_size_bytes
            } else {
                0
            },
        )),
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
        // runs the single self-contained app layer with no base/runtime). A static
        // target ignores this — its lifecycle path always packs a flat
        // `/out/static.tar.gz`.
        export_layered: true,
        // Function targets run the in-VM function-builder (→ /out/function.wasm) and
        // static targets run the buildpack pipeline → /out/static.tar.gz; both ignore
        // the server export mode above. The two kind flags are mutually exclusive.
        build_function: matches!(spec.kind, TargetKind::Function),
        build_static: matches!(spec.kind, TargetKind::Static),
        builder_hint: is_dockerfile.then(|| "dockerfile".to_string()),
        dockerfile: spec.dockerfile.clone(),
        // The subdir WITHIN the mounted context where detect/build run. `"."` (context
        // unset) keeps the buildpack's app_dir at the context root — today's behaviour.
        // The `dockerfile` path above stays relative to THIS subdir (= app_dir).
        build_subdir: Some(spec.build_subdir.clone()),
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
            bail!(
                "build timed out after {}s\n{}",
                deps.timeout.as_secs(),
                log_str()
            )
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
            let dest = staged
                .join("_functions")
                .join(format!("{}.wasm", spec.name));
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
        TargetKind::Static => {
            collect_static_site(&output_img, staged, workspace, &tag, config, spec)?;
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
        bail!(
            "server build produced no {} (expected a layered export)",
            jkbuild_types::out::INDEX
        );
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
    ensure!(
        app.media == "erofs",
        "unexpected app layer media {:?}",
        app.media
    );

    // The blob filename becomes a dest path — it is fully attacker-controlled, so
    // bound it to `sha256-<64hex>.erofs` (no separators, no traversal).
    let file = app.file.clone();
    ensure!(
        is_safe_blob_filename(&file),
        "unsafe app layer filename {file:?}"
    );

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
        obj.insert(
            "app_digest".to_string(),
            serde_json::Value::String(app.digest.clone()),
        );
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
    std::fs::write(
        staged.join("_servers").join(format!("{}.json", spec.name)),
        json,
    )?;
    Ok(())
}

/// Collect a static build target: dump the build VM's plain `/static.tar.gz`
/// (trunk's `dist/`, etc.), untar it in a scratch dir, then copy the tree into the
/// staged SITE location — the same place `assemble_sites` copies committed static
/// content. A built site thus replaces "commit your pre-built dist/" with "the
/// platform builds it server-side", with no other change to the serving path.
///
/// Destination mirrors `assemble_sites`: the staged ROOT for the single default
/// site (guarded against `_`-prefixed clobbers, review B-1), or `_site_<name>/` for
/// a named site in a multi-site deploy. The copy reuses the SAME guard as committed
/// content, so a built tree gets no extra trust.
fn collect_static_site(
    output_img: &Path,
    staged: &Path,
    workspace: &Path,
    tag: &str,
    config: &ProjectConfig,
    spec: &TargetSpec,
) -> Result<()> {
    // 1. Dump the plain tarball the lifecycle's static path wrote.
    let tar_tmp = workspace.join(format!("{tag}.static.tar.gz"));
    if !build_output::dump_file(output_img, jkbuild_types::out::STATIC_TARBALL, &tar_tmp)? {
        bail!(
            "static build produced no {} (expected a flat static export)",
            jkbuild_types::out::STATIC_TARBALL
        );
    }

    // 2. Untar into a scratch dir (tar-rs refuses `..`/absolute escapes; the
    //    hostile-code boundary remains the build VM, this is defense-in-depth).
    let extract = workspace.join(format!("{tag}.static-tree"));
    let _ = std::fs::remove_dir_all(&extract);
    std::fs::create_dir_all(&extract)?;
    let bytes = std::fs::read(&tar_tmp)
        .with_context(|| format!("read dumped static tarball {}", tar_tmp.display()))?;
    unpack_tar_gz(&bytes, &extract).context("unpack built static tarball")?;
    let _ = std::fs::remove_file(&tar_tmp);

    // 3. Resolve the staged site destination, mirroring assemble_sites' placement.
    //    A built site is named after its `[sites.<name>]` (the Static target name); a
    //    single default site lands at the staged root.
    if config.is_multi_site() {
        // Named site → its own `_site_<name>/` prefix (no top-level guard needed —
        // the whole subtree is namespaced and the agent serves it under the prefix).
        let dest = staged.join(format!("_site_{}", spec.name));
        let _ = std::fs::remove_dir_all(&dest);
        copy_filtered(&extract, &dest)?;
    } else {
        // Single default site → the staged ROOT alongside the host's `_`-prefixed
        // control artifacts; guard against a built tree clobbering them (review B-1).
        copy_filtered_guarded(&extract, staged)?;
    }
    let _ = std::fs::remove_dir_all(&extract);
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
fn read_built_manifest(
    output_img: &Path,
    workspace: &Path,
    tag: &str,
) -> Result<BuiltServerManifest> {
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

/// Copy a tenant-named `[database]` file (`schema`/`rules`) from the uploaded source tree
/// into the host-controlled `_database/` staging dir — **symlink-safe**. The source tar is
/// tenant-controlled and `unpack_tar_gz` preserves symlinks, while `std::fs::copy` follows
/// them, so a `schema.rhype` (or a symlinked parent component) pointing at a host path would
/// otherwise exfiltrate an arbitrary HOST file (e.g. /etc/passwd, another tenant's tree)
/// into the guest-readable metadata image. `path_ok` already rejected `..`/absolute STRINGS;
/// this closes the symlink hole by canonicalizing the resolved source and requiring it to
/// stay inside the project tree (and be a regular file). Mirrors the symlink-skipping
/// discipline `assemble_sites`/`copy_filtered_inner` already use for committed site content.
fn stage_db_file(src_dir: &Path, rel: &str, dest: &Path) -> Result<()> {
    let base = src_dir
        .canonicalize()
        .context("canonicalize project source dir")?;
    let src = base
        .join(rel)
        .canonicalize()
        .with_context(|| format!("resolve [database] file {rel:?}"))?;
    ensure!(
        src.starts_with(&base),
        "[database] file {rel:?} resolves outside the project tree (symlink?) — refusing"
    );
    ensure!(
        src.is_file(),
        "[database] file {rel:?} is not a regular file"
    );
    std::fs::copy(&src, dest).with_context(|| format!("stage DB file {rel:?}"))?;
    Ok(())
}

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
            bail!(
                "function '{name}' source {:?} must be a relative path inside the project (no '..' or absolute)",
                f.source
            );
        }
        // `egress = []` is ambiguous: [] and `false` are identical for the PUBLIC zone, but
        // an author writing [] to mean "deny everything incl. own-stuff" would be surprised
        // that own-stuff still works. Make it un-writable rather than silently alias it to
        // `false` (design §3 edge case). Point them at the explicit spelling.
        if matches!(&f.egress, Some(EgressPolicy::Allowlist(a)) if a.is_empty()) {
            bail!(
                "function '{name}' has `egress = []` (empty allowlist); use `egress = false` to deny all public egress, or list the allowed hosts"
            );
        }
    }
    if matches!(
        config.hosting.as_ref().and_then(|h| h.function_egress.as_ref()),
        Some(EgressPolicy::Allowlist(a)) if a.is_empty()
    ) {
        bail!(
            "[hosting] function_egress = [] (empty allowlist); use `false` to sandbox every function, or list the allowed hosts"
        );
    }
    // The `source` of a target must live INSIDE its build `context` — otherwise the
    // wider mount wouldn't contain the source subdir the build runs in. `context`
    // defaults to `source`, so an unset `context` (source == context) trivially holds.
    // Both strings are already individually `path_ok`-checked by the caller (no
    // `..`/absolute escapes); this is purely the containment relation.
    fn source_within_context(context: &str, source: &str) -> bool {
        let c = context.trim_start_matches("./").trim_end_matches('/');
        let s = source.trim_start_matches("./").trim_end_matches('/');
        c.is_empty() || c == "." || s == c || s.starts_with(&format!("{c}/"))
    }
    for (name, s) in &config.servers {
        let sd = s.source_dir();
        if !path_ok(sd) {
            bail!(
                "server '{name}' source {sd:?} must be a relative path inside the project (no '..' or absolute)"
            );
        }
        let ctx = s.context_dir();
        if !path_ok(ctx) {
            bail!(
                "server '{name}' context {ctx:?} must be a relative path inside the project (no '..' or absolute)"
            );
        }
        if !source_within_context(ctx, sd) {
            bail!("server '{name}' source {sd:?} must be inside its build context {ctx:?}");
        }
        // When `context` widens the mount, `source`-within-`context` rides the kernel
        // cmdline as `jkbase.build_subdir=`. `path_ok` permits chars the cmdline guard
        // rejects (e.g. a space), and the emitter would then SILENTLY drop the token and
        // build at the context root — fail loud at deploy instead. (No-op for the common
        // `build_subdir == "."`, so a plain non-monorepo source is unaffected.)
        let bs = s.build_subdir();
        if bs != "." && !is_safe_cmdline_path(&bs) {
            bail!(
                "server '{name}' source {sd:?} within context {ctx:?} yields a build subdir {bs:?} with characters that can't be passed to the build VM — use only [A-Za-z0-9._/-]"
            );
        }
        // builder = auto|dockerfile, and (for dockerfile) language/dockerfile coherence.
        s.validate(name)?;
        // The Dockerfile must live inside the project tree (it becomes a /src path).
        if s.builder()? == Builder::Dockerfile {
            let df = s.dockerfile_path();
            if !path_ok(&df) {
                bail!(
                    "server '{name}' dockerfile {df:?} must be a relative path inside the project (no '..' or absolute)"
                );
            }
        }
    }
    for (name, site) in &config.sites {
        // `build = "..."` resolves (reject a typo'd strategy that would otherwise ship
        // un-built source as static content).
        let build = site
            .build_strategy()
            .with_context(|| format!("site '{name}' build strategy"))?;
        if build.is_some() {
            // A BUILT site: its `source` (not `public`) must be a safe relative path,
            // and (when set) its `context` must be safe and contain that source.
            let src = site.build_source();
            if !path_ok(src) {
                bail!(
                    "site '{name}' source {src:?} must be a relative path inside the project (no '..' or absolute)"
                );
            }
            let ctx = site.context_dir();
            if !path_ok(ctx) {
                bail!(
                    "site '{name}' context {ctx:?} must be a relative path inside the project (no '..' or absolute)"
                );
            }
            if !source_within_context(ctx, src) {
                bail!("site '{name}' source {src:?} must be inside its build context {ctx:?}");
            }
            // Same as servers: a `context`-derived build subdir must be cmdline-safe so
            // the `jkbase.build_subdir=` token isn't silently dropped (→ build at the
            // context root). No-op when `build_subdir == "."` (no `context` widening).
            let bs = site.build_subdir();
            if bs != "." && !is_safe_cmdline_path(&bs) {
                bail!(
                    "site '{name}' source {src:?} within context {ctx:?} yields a build subdir {bs:?} with characters that can't be passed to the build VM — use only [A-Za-z0-9._/-]"
                );
            }
        } else {
            // A COMMITTED site: `public` is REQUIRED. Omitting it must NOT silently
            // default to the project root — that would package the entire source tree
            // (Cargo/JS source, configs, …) as served site content, the exact footgun
            // resolved_sites' synthesize path guards against. Only a built site may omit
            // `public` (its slot is filled from the build output).
            let Some(public) = site.public.as_deref() else {
                bail!(
                    "site '{name}' must set `public` (the committed static directory) unless it sets `build`"
                );
            };
            if !path_ok(public) {
                bail!(
                    "site '{name}' public {public:?} must be a relative path inside the project (no '..' or absolute)"
                );
            }
        }
    }
    if let Some(public) = config.hosting.as_ref().and_then(|h| h.public.as_deref())
        && !path_ok(public)
    {
        bail!(
            "hosting public {public:?} must be a relative path inside the project (no '..' or absolute)"
        );
    }
    // Managed DB: the engine resolves (reject unknown) + a non-empty schema, and the
    // schema/rules paths are traversal-guarded — run_inner copies them host-side from
    // the source tree, so an unguarded `..`/absolute would read outside the project.
    if let Some(db) = &config.database {
        db.validate().context("[database] section")?;
        if !path_ok(&db.schema) {
            bail!(
                "[database] schema {:?} must be a relative path inside the project (no '..' or absolute)",
                db.schema
            );
        }
        if let Some(rules) = &db.rules
            && !path_ok(rules)
        {
            bail!(
                "[database] rules {:?} must be a relative path inside the project (no '..' or absolute)",
                rules
            );
        }
    }

    // Raw L4 ingress ports: each `[l4.<name>]` resolves its proto (reject unknown), has a
    // non-zero `guest_port`, and — in v1 — is UDP (TCP rejected until the follow-on data
    // path lands). Fail-closed so a typo'd proto or an unbuilt transport aborts the deploy
    // rather than allocating a dead public port. See docs/managed-l4-udp-ingress-design.md.
    for (name, l4) in &config.l4 {
        l4.validate(name)
            .with_context(|| format!("[l4.{name}] section"))?;
    }

    // The managed DB is supervised in-VM under the reserved server name `rhypedb` and is
    // loopback-only / NEVER routed. Fence that name from tenant input on both axes,
    // fail-closed at deploy: (1) a tenant server/function/site named `rhypedb` would
    // collide with the DB in the agent's supervised set; (2) a tenant ROUTE targeting
    // `rhypedb` would make the agent proxy EXTERNAL traffic to 127.0.0.1:4200 — including
    // the DB's unauthenticated admin plane — defeating the never-routed invariant (the
    // agent resolves a route to ANY supervised server of that name).
    let reserved = crate::layer_plan::RHYPEDB_RUNTIME;
    for (kind, name) in config
        .functions
        .keys()
        .map(|n| ("function", n))
        .chain(config.servers.keys().map(|n| ("server", n)))
        .chain(config.sites.keys().map(|n| ("site", n)))
    {
        if name == reserved {
            bail!("{kind} name {name:?} is reserved for the managed database");
        }
    }
    for (pattern, target) in &config.routes {
        if target.name == reserved {
            bail!(
                "route {pattern:?} targets reserved name {reserved:?}: the managed database \
                 is loopback-only and cannot be routed"
            );
        }
    }
    Ok(())
}

fn enumerate_targets(config: &ProjectConfig) -> Vec<TargetSpec> {
    let mut specs: Vec<TargetSpec> = Vec::new();
    for (name, f) in &config.functions {
        specs.push(TargetSpec {
            name: name.clone(),
            kind: TargetKind::Function,
            // Functions have no `context` knob (they take the wasm path); the context is
            // the source and the build runs at its root — identical to before.
            context_subdir: f.source.clone(),
            build_subdir: ".".to_string(),
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
            // Context defaults to `source` → build_subdir "." (today's behaviour). When
            // `context` is set wider, mount it and build in the source subdir within it.
            context_subdir: s.context_dir().to_string(),
            build_subdir: s.build_subdir(),
            language: s.language.clone(),
            builder,
            dockerfile,
        });
    }
    // Built sites ([sites.<name>] with `build = "..."`): one static build target each,
    // building from `source` and producing a static tree the host serves as that site.
    // The build strategy (trunk) selects the in-VM buildpack via the language hint.
    for (name, site) in &config.sites {
        // `build` was validated at intake; ignore an (already-rejected) bad value here.
        let Ok(Some(strategy)) = site.build_strategy() else {
            continue;
        };
        let language = match strategy {
            jkbase_common::config::SiteBuild::Trunk => Some("trunk".to_string()),
        };
        specs.push(TargetSpec {
            name: name.clone(),
            kind: TargetKind::Static,
            // Context defaults to `source` → build_subdir "." (today's behaviour). A
            // wider `context` lets a trunk frontend resolve in-repo sibling path-deps.
            context_subdir: site.context_dir().to_string(),
            build_subdir: site.build_subdir(),
            language,
            builder: Builder::Auto, // built sites take the buildpack path, never a Dockerfile
            dockerfile: None,
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
    // Managed DB marker (engine/schema/rules; NEVER the admin token — that rides the
    // reserved channel, injected host-side at build_metadata_image). Its presence drives
    // both compute_layer_plan (attach the rhypedb runtime) and the agent's DB supervisor.
    if let Some(j) = config.database_json() {
        std::fs::write(staged.join("_database.json"), j)?;
    }

    // Stamp each function's RESOLVED public-egress policy into its `_functions/{name}.json`
    // sidecar. Precedence (project ceiling × per-function) is collapsed HERE, host-side,
    // into one concrete `ResolvedEgress` so the agent receives exactly one immutable state
    // and never parses `jkbase.toml` nor re-derives precedence (P0-EGRESS-POLICY-HOST-
    // RESOLVED). Written before the `.wasm` is staged and before deploy-time secret
    // injection, both of which merge into (never clobber) this sidecar.
    if !config.functions.is_empty() {
        let functions_dir = staged.join("_functions");
        std::fs::create_dir_all(&functions_dir)?;
        let project_ceiling = config
            .hosting
            .as_ref()
            .and_then(|h| h.function_egress.as_ref());
        for (name, f) in &config.functions {
            let resolved = resolve_egress(project_ceiling, f.egress.as_ref());
            let sidecar = functions_dir.join(format!("{name}.json"));
            // Merge into any existing sidecar (preserve a future `runtime`/`env`); create
            // it otherwise. Only the `egress` key is host-authored here.
            let mut obj: serde_json::Value = match std::fs::read(&sidecar) {
                Ok(bytes) => serde_json::from_slice(&bytes)
                    .with_context(|| format!("parse function sidecar {}", sidecar.display()))?,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => serde_json::json!({}),
                Err(e) => return Err(e).with_context(|| format!("read {}", sidecar.display())),
            };
            if let Some(map) = obj.as_object_mut() {
                map.insert("egress".to_string(), serde_json::to_value(&resolved)?);
                std::fs::write(&sidecar, serde_json::to_vec_pretty(&obj)?)?;
            }
        }
    }
    Ok(())
}

fn assemble_sites(config: &ProjectConfig, src_dir: &Path, staged: &Path) -> Result<()> {
    let sites = config.resolved_sites();
    if config.is_multi_site() {
        for site in &sites {
            // A BUILT site's content comes from its static build target (collected
            // post-build into the same `_site_<name>/` slot), not from committed source.
            if site.built {
                continue;
            }
            let site_dir = src_dir.join(&site.public);
            if site_dir.is_dir() {
                copy_filtered(&site_dir, &staged.join(format!("_site_{}", site.name)))?;
            }
        }
    } else if let Some(site) = sites.first() {
        // Skip the committed-copy for a built default site — the static build fills the
        // staged root.
        if site.built {
            return Ok(());
        }
        let site_dir = src_dir.join(&site.public);
        if site_dir.is_dir() {
            // Single-site content lands in the staged ROOT alongside the host's `_`-prefixed
            // control artifacts — guard against a tenant clobbering them (review B-1).
            copy_filtered_guarded(&site_dir, staged)?;
        }
    }
    Ok(())
}

/// Recursively copy `src` into `dst`, skipping the build/VCS dirs and manifest
/// files (mirrors the CLI's old packaging exclusions). Symlinks are skipped.
fn copy_filtered(src: &Path, dst: &Path) -> Result<()> {
    copy_filtered_inner(src, dst, false)
}

/// As [`copy_filtered`], but REFUSES any TOP-LEVEL entry whose name begins with `_`.
/// Used for the single-site copy into the staged ROOT, where the host's own
/// `_`-prefixed control artifacts live (`_functions/`, `_routes.json`, `_platform.json`,
/// `_servers/`, …). Without this a tenant whose site is the project root (`public = "."`)
/// could smuggle a `_functions/<fn>.json` into their source tree that overwrites the
/// host-authored, precedence-resolved egress sidecar — escaping its own `egress = false`
/// or widening past a project ceiling (adversarial-review BLOCKER B-1,
/// P0-EGRESS-POLICY-HOST-RESOLVED). The agent's static server already refuses to SERVE
/// `_`-prefixed top-level entries, so refusing to COPY them loses nothing legitimate.
/// (Site SUBdirs like `_next/` remain fine — the guard is top-level only, and multi-site
/// content lands under a namespaced `_site_<name>/`, not the root.)
fn copy_filtered_guarded(src: &Path, dst: &Path) -> Result<()> {
    copy_filtered_inner(src, dst, true)
}

fn copy_filtered_inner(src: &Path, dst: &Path, guard_top_underscore: bool) -> Result<()> {
    std::fs::create_dir_all(dst)?;
    for entry in std::fs::read_dir(src)? {
        let entry = entry?;
        let name = entry.file_name();
        let name_str = name.to_string_lossy();
        // Top-level `_`-prefixed entries collide with host control artifacts — never copy
        // them from tenant content into the staged root.
        if guard_top_underscore && name_str.starts_with('_') {
            warn!(entry = %name_str, "refusing to copy a tenant `_`-prefixed top-level entry into the deployment root");
            continue;
        }
        let ft = entry.file_type()?;
        if ft.is_symlink() {
            continue;
        } else if ft.is_dir() {
            if EXCLUDED_DIRS.contains(&name_str.as_ref()) {
                continue;
            }
            // The guard is top-level only; subdirectories may legitimately hold `_`-prefixed
            // framework dirs (e.g. `_next/`).
            copy_filtered_inner(&entry.path(), &dst.join(&name), false)?;
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
        TargetKind::Static => "static",
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
        // No `context` set → context is the source, build at its root (regression guard
        // for the default path: identical to the pre-`context` single-subdir mount).
        assert_eq!(specs[2].context_subdir, "./server");
        assert_eq!(specs[2].build_subdir, ".");
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
        assert_eq!(specs[0].context_subdir, "./api"); // /src = ./api
        assert_eq!(specs[0].build_subdir, "."); // build at the context root
        assert_eq!(specs[0].dockerfile.as_deref(), Some("Dockerfile")); // relative to app_dir

        // Explicit source + nested dockerfile → relpath strips the source prefix.
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nbuilder = \"dockerfile\"\nsource = \".\"\ndockerfile = \"docker/api.Dockerfile\"\nport = 3000\n",
        )
        .unwrap();
        let specs = enumerate_targets(&cfg);
        assert_eq!(
            specs[0].dockerfile.as_deref(),
            Some("docker/api.Dockerfile")
        );
    }

    #[test]
    fn enumerate_built_site_emits_static_target() {
        // A `[sites.<name>]` with `build = "trunk"` enumerates a Static target whose
        // source is the site's `source`, language "trunk", no dockerfile.
        let cfg: ProjectConfig = toml::from_str(
            r#"
            [sites.app]
            source = "./web"
            build = "trunk"
            "#,
        )
        .unwrap();
        let specs = enumerate_targets(&cfg);
        assert_eq!(specs.len(), 1);
        assert_eq!(specs[0].kind, TargetKind::Static);
        assert_eq!(specs[0].name, "app");
        assert_eq!(specs[0].context_subdir, "./web");
        assert_eq!(specs[0].build_subdir, ".");
        assert_eq!(specs[0].language.as_deref(), Some("trunk"));
        assert_eq!(specs[0].builder, Builder::Auto);
        assert!(specs[0].dockerfile.is_none());

        // A COMMITTED site (no `build`) enumerates NO build target — it's copied
        // from source by assemble_sites, unchanged.
        let committed: ProjectConfig =
            toml::from_str("[sites.docs]\npublic = \"./docs\"\n").unwrap();
        assert!(enumerate_targets(&committed).is_empty());
    }

    #[test]
    fn static_target_kind_name_and_static_tarball_contract() {
        assert_eq!(kind_name(TargetKind::Static), "static");
        // The host reads the lifecycle's static export by this fixed name.
        assert_eq!(jkbuild_types::out::STATIC_TARBALL, "/static.tar.gz");
    }

    #[test]
    fn proxy_url_selects_public_any_only_for_dockerfile() {
        // With a distinct any-port, dockerfile builds get it; others get the narrow proxy.
        let net = BuildNet::new(
            "jkbuild0".into(),
            "172.31.0.1".into(),
            3128,
            Some(3129),
            100_000,
            8,
        );
        assert_eq!(net.proxy_url_for(false), "http://172.31.0.1:3128");
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3129");
        assert_eq!(net.proxy_any_port, Some(3129));

        // any-port == proxy_port disables the second proxy (dockerfile shares narrow).
        let net = BuildNet::new(
            "jkbuild0".into(),
            "172.31.0.1".into(),
            3128,
            Some(3128),
            100_000,
            8,
        );
        assert_eq!(net.proxy_any_port, None);
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3128");

        // No any-port → dockerfile falls back to the narrow proxy.
        let net = BuildNet::new(
            "jkbuild0".into(),
            "172.31.0.1".into(),
            3128,
            None,
            100_000,
            8,
        );
        assert_eq!(net.proxy_url_for(true), "http://172.31.0.1:3128");
    }

    #[test]
    fn per_lease_any_egress_rule_is_source_scoped() {
        // The per-lease grant pins BOTH the source guest IP and the gateway:port, so
        // it admits exactly one VM to the public-any proxy — and `-C` without `-s`
        // (verify_firewall's blanket-rule check) cannot match it.
        let net = BuildNet::new(
            "jkbuild0".into(),
            "172.31.0.1".into(),
            3128,
            Some(3129),
            100_000,
            8,
        );
        assert_eq!(
            net.any_egress_rule("172.31.0.5", 3129),
            vec![
                "-s",
                "172.31.0.5",
                "-p",
                "tcp",
                "-d",
                "172.31.0.1",
                "--dport",
                "3129",
                "-j",
                "ACCEPT",
            ]
        );
    }

    #[test]
    fn dockerfile_relpath_strips_source_prefix() {
        assert_eq!(
            dockerfile_relpath("./api/Dockerfile", "./api"),
            "Dockerfile"
        );
        assert_eq!(dockerfile_relpath("Dockerfile", "."), "Dockerfile");
        assert_eq!(
            dockerfile_relpath("docker/Dockerfile", "."),
            "docker/Dockerfile"
        );
        assert_eq!(
            dockerfile_relpath("svc/sub/Dockerfile", "svc"),
            "sub/Dockerfile"
        );
        // Dockerfile not under the source dir (misconfig) → returned unchanged.
        assert_eq!(
            dockerfile_relpath("other/Dockerfile", "svc"),
            "other/Dockerfile"
        );
    }

    #[test]
    fn sidecars_written_only_when_present() {
        let dir = std::env::temp_dir().join(format!("jkb-asm-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg: ProjectConfig =
            toml::from_str("[routes.\"a.example.com\"]\nservice = \"function\"\nname = \"api\"\n")
                .unwrap();
        assemble_sidecars(&cfg, &dir).unwrap();
        assert!(dir.join("_routes.json").exists());
        assert!(!dir.join("_sites.json").exists());
        assert!(!dir.join("_schedules.json").exists());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn assemble_sidecars_stamps_resolved_function_egress() {
        let dir = std::env::temp_dir().join(format!("jkb-fnegress-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Project ceiling = allowlist; one fn narrows (intersect), one omits (=ceiling),
        // one sandboxes. Verifies the host collapses precedence into the sidecar.
        let cfg: ProjectConfig = toml::from_str(
            r#"
            [hosting]
            function_egress = ["api.stripe.com", "api.twilio.com"]
            [functions.narrow]
            source = "narrow"
            egress = ["api.stripe.com", "evil.com"]
            [functions.inherit]
            source = "inherit"
            [functions.boxed]
            source = "boxed"
            egress = false
            "#,
        )
        .unwrap();
        assemble_sidecars(&cfg, &dir).unwrap();

        let read = |n: &str| -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(dir.join("_functions").join(n)).unwrap()).unwrap()
        };
        // evil.com intersected out of the ceiling.
        assert_eq!(
            read("narrow.json")["egress"]["allowlist"],
            serde_json::json!(["api.stripe.com"])
        );
        // Omitted → the project ceiling verbatim (NOT allow-all).
        let inherit = read("inherit.json");
        let mut got: Vec<String> = inherit["egress"]["allowlist"]
            .as_array()
            .unwrap()
            .iter()
            .map(|v| v.as_str().unwrap().to_string())
            .collect();
        got.sort();
        assert_eq!(
            got,
            vec!["api.stripe.com".to_string(), "api.twilio.com".to_string()]
        );
        // `false` → sandbox (snake_case unit variant).
        assert_eq!(read("boxed.json")["egress"], serde_json::json!("sandbox"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_filtered_guarded_refuses_underscore_toplevel() {
        // B-1: a tenant whose single-site root (`public = "."`) carries a planted
        // `_functions/<fn>.json` must NOT clobber the host-authored sidecar. The guarded copy
        // refuses `_`-prefixed TOP-LEVEL entries but keeps ordinary content and nested
        // `_`-prefixed framework dirs.
        let base = std::env::temp_dir().join(format!("jkb-guard-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let src = base.join("src");
        let dst = base.join("dst");
        std::fs::create_dir_all(src.join("_functions")).unwrap();
        std::fs::create_dir_all(src.join("sub/_next")).unwrap();
        std::fs::write(src.join("_functions/api.json"), "{\"egress\":\"default\"}").unwrap();
        std::fs::write(src.join("_routes.json"), "tenant").unwrap();
        std::fs::write(src.join("index.html"), "hi").unwrap();
        std::fs::write(src.join("sub/_next/app.js"), "ok").unwrap();

        copy_filtered_guarded(&src, &dst).unwrap();

        // Top-level `_`-prefixed tenant entries refused…
        assert!(
            !dst.join("_functions").exists(),
            "top-level _functions must be refused"
        );
        assert!(
            !dst.join("_routes.json").exists(),
            "top-level _routes.json must be refused"
        );
        // …ordinary content + NESTED `_`-prefixed dirs preserved.
        assert!(dst.join("index.html").exists());
        assert!(
            dst.join("sub/_next/app.js").exists(),
            "nested _next is fine (guard is top-level only)"
        );
        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn validate_rejects_unsafe_site_name() {
        // The multi-site `_site_<name>` copy uses the site KEY verbatim; validate_manifest's
        // name_ok gate (runs before assemble_sites) rejects any `/`-or-`..` key, so a
        // `../_functions` site cannot traverse into the host artifact dir.
        let cfg: ProjectConfig =
            toml::from_str("[sites.\"../_functions\"]\npublic = \"x\"\n").unwrap();
        let err = validate_manifest(&cfg).unwrap_err().to_string();
        assert!(err.contains("invalid site name"), "got: {err}");
    }

    #[test]
    fn validate_rejects_empty_egress_allowlist() {
        let fn_empty: ProjectConfig =
            toml::from_str("[functions.api]\nsource = \"api\"\negress = []\n").unwrap();
        let err = validate_manifest(&fn_empty).unwrap_err().to_string();
        assert!(err.contains("egress = []"), "got: {err}");

        let proj_empty: ProjectConfig =
            toml::from_str("[hosting]\nfunction_egress = []\n[functions.api]\nsource = \"api\"\n")
                .unwrap();
        assert!(
            validate_manifest(&proj_empty)
                .unwrap_err()
                .to_string()
                .contains("function_egress = []")
        );

        // A non-empty allowlist is fine.
        let ok: ProjectConfig =
            toml::from_str("[functions.api]\nsource = \"api\"\negress = [\"api.stripe.com\"]\n")
                .unwrap();
        assert!(validate_manifest(&ok).is_ok());
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
            [
                "bun.ext4",
                "jkbuild-server.ext4",
                "server.ext4",
                "default.ext4"
            ]
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
        // A STATIC target keys on language like a server (kind != function), so a
        // trunk static site picks `trunk.ext4` first.
        assert_eq!(
            toolchain_candidates("static", Some("trunk")),
            [
                "trunk.ext4",
                "jkbuild-static.ext4",
                "static.ext4",
                "default.ext4"
            ]
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
        std::fs::write(
            dir.join("package.json"),
            r#"{"packageManager":"bun@1.1.34"}"#,
        )
        .unwrap();
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
        let abs: ProjectConfig = toml::from_str("[functions.api]\nsource = \"/etc\"\n").unwrap();
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

        // A COMMITTED site that OMITS `public` → reject. Without this guard the missing
        // `public` would default to the project root and silently serve the whole source
        // tree as site content (information disclosure on an all-tenants-untrusted host).
        let no_public: ProjectConfig =
            toml::from_str("[sites.docs]\nprefix = \"/docs\"\n").unwrap();
        let err = validate_manifest(&no_public).unwrap_err().to_string();
        assert!(err.contains("must set `public`"), "got: {err}");

        // A BUILT site is the ONLY one allowed to omit `public` (its slot is filled from
        // the build output) — must still pass.
        let built: ProjectConfig =
            toml::from_str("[sites.app]\nsource = \"./web\"\nbuild = \"trunk\"\n").unwrap();
        assert!(validate_manifest(&built).is_ok());

        // Name with a path separator → reject (would escape the staged dest).
        let badname: ProjectConfig =
            toml::from_str("[functions.\"../../evil\"]\nsource = \"./x\"\n").unwrap();
        assert!(validate_manifest(&badname).is_err());

        // hosting.public traversal → reject.
        let host: ProjectConfig = toml::from_str("[hosting]\npublic = \"../..\"\n").unwrap();
        assert!(validate_manifest(&host).is_err());
    }

    #[test]
    fn validate_manifest_build_context_rules() {
        // Server: a wider context that CONTAINS the source → ok.
        let ok: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"crates/api\"\ncontext = \".\"\nport = 80\n")
                .unwrap();
        assert!(validate_manifest(&ok).is_ok());

        // Context = parent dir of source → ok.
        let nested: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"apps/api\"\ncontext = \"apps\"\nport = 80\n")
                .unwrap();
        assert!(validate_manifest(&nested).is_ok());

        // Source OUTSIDE the context (sibling, not contained) → reject.
        let outside: ProjectConfig = toml::from_str(
            "[servers.web]\nsource = \"services/api\"\ncontext = \"apps\"\nport = 80\n",
        )
        .unwrap();
        let err = validate_manifest(&outside).unwrap_err().to_string();
        assert!(
            err.contains("must be inside its build context"),
            "got: {err}"
        );

        // `..` escape in context → reject.
        let escape: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"api\"\ncontext = \"../..\"\nport = 80\n")
                .unwrap();
        assert!(validate_manifest(&escape).is_err());

        // Absolute context → reject.
        let abs: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"api\"\ncontext = \"/etc\"\nport = 80\n")
                .unwrap();
        assert!(validate_manifest(&abs).is_err());

        // Built SITE with a containing context → ok; sibling context → reject.
        let site_ok: ProjectConfig =
            toml::from_str("[sites.app]\nsource = \"web\"\ncontext = \".\"\nbuild = \"trunk\"\n")
                .unwrap();
        assert!(validate_manifest(&site_ok).is_ok());
        let site_bad: ProjectConfig = toml::from_str(
            "[sites.app]\nsource = \"frontend/web\"\ncontext = \"backend\"\nbuild = \"trunk\"\n",
        )
        .unwrap();
        assert!(validate_manifest(&site_bad).is_err());

        // A `context`-derived build subdir with a cmdline-unsafe char (a space) →
        // reject at deploy. `path_ok` alone would PASS this (it permits spaces), but
        // the `jkbase.build_subdir=` emitter would then silently drop the token and
        // build at the context root. Guard so the failure is a clear deploy error.
        let spacey: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"my app\"\ncontext = \".\"\nport = 80\n")
                .unwrap();
        let err = validate_manifest(&spacey).unwrap_err().to_string();
        assert!(
            err.contains("can't be passed to the build VM"),
            "got: {err}"
        );
        // …but the SAME spacey source with NO `context` is unchanged (build_subdir is
        // ".", no token emitted) — today's behaviour must still validate.
        let spacey_ok: ProjectConfig =
            toml::from_str("[servers.web]\nsource = \"my app\"\nport = 80\n").unwrap();
        assert!(validate_manifest(&spacey_ok).is_ok());
    }

    #[test]
    fn enumerate_targets_threads_context_and_build_subdir() {
        // A monorepo server: `context = "."`, `source = "crates/api"` → mount root,
        // build in crates/api. The default-path targets keep build_subdir ".".
        let cfg: ProjectConfig = toml::from_str(
            "[servers.api]\nsource = \"crates/api\"\ncontext = \".\"\nport = 3000\n[servers.plain]\nsource = \"svc\"\nport = 3001\n",
        )
        .unwrap();
        let specs = enumerate_targets(&cfg);
        let api = specs.iter().find(|s| s.name == "api").unwrap();
        assert_eq!(api.context_subdir, ".");
        assert_eq!(api.build_subdir, "crates/api");
        let plain = specs.iter().find(|s| s.name == "plain").unwrap();
        assert_eq!(plain.context_subdir, "svc");
        assert_eq!(plain.build_subdir, "."); // unset context → identical to today

        // Built site with a wider context.
        let site_cfg: ProjectConfig =
            toml::from_str("[sites.app]\nsource = \"web\"\ncontext = \".\"\nbuild = \"trunk\"\n")
                .unwrap();
        let s = &enumerate_targets(&site_cfg)[0];
        assert_eq!(s.context_subdir, ".");
        assert_eq!(s.build_subdir, "web");
    }

    #[test]
    fn validate_manifest_reserves_managed_db_name_and_route() {
        // A tenant ROUTE targeting the managed DB's reserved name would make the agent
        // proxy EXTERNAL traffic to the loopback-only DB (incl. its unauthenticated admin
        // plane) — reject at deploy.
        let routed: ProjectConfig = toml::from_str(
            "[database]\nschema = \"s.rhype\"\n[routes.\"/db\"]\nservice = \"server\"\nname = \"rhypedb\"\n",
        )
        .unwrap();
        let err = validate_manifest(&routed).unwrap_err().to_string();
        assert!(err.contains("reserved"), "got: {err}");

        // The reserved name is also fenced from server/site/function names (a collision
        // with the DB in the agent's supervised set).
        for sec in [
            "[servers.rhypedb]\nsource = \"./s\"\nport = 80\n",
            "[sites.rhypedb]\npublic = \"./s\"\n",
            "[functions.rhypedb]\nsource = \"./f\"\n",
        ] {
            let c: ProjectConfig = toml::from_str(sec).unwrap();
            assert!(
                validate_manifest(&c).is_err(),
                "must reserve `rhypedb` in: {sec}"
            );
        }

        // A normal route + normal names still pass.
        let ok: ProjectConfig = toml::from_str(
            "[servers.api]\nsource = \"./a\"\nport = 80\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n",
        )
        .unwrap();
        assert!(validate_manifest(&ok).is_ok());
    }

    #[test]
    fn stage_db_file_refuses_symlink_escape() {
        // The uploaded source tar is tenant-controlled and preserves symlinks; a symlinked
        // schema/rules pointing at a host path must NOT be copied into the staged artifact
        // (which is baked into the guest-readable metadata image).
        let tmp = std::env::temp_dir().join(format!("jkb-stagedb-{}", std::process::id()));
        let src = tmp.join("src");
        let out = tmp.join("out");
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(&src).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        // A host secret OUTSIDE the project tree.
        let secret = tmp.join("host-secret");
        std::fs::write(&secret, b"TOPSECRET").unwrap();

        // schema.rhype is a symlink escaping the project tree → refused, nothing staged.
        std::os::unix::fs::symlink(&secret, src.join("schema.rhype")).unwrap();
        let dest = out.join("schema.rhype");
        assert!(stage_db_file(&src, "schema.rhype", &dest).is_err());
        assert!(!dest.exists(), "host secret must not be staged");

        // A regular in-tree file → copied fine.
        std::fs::write(src.join("ok.rhype"), b"type User { name: String }").unwrap();
        let dest_ok = out.join("ok.rhype");
        stage_db_file(&src, "ok.rhype", &dest_ok).unwrap();
        assert_eq!(
            std::fs::read(&dest_ok).unwrap(),
            b"type User { name: String }"
        );

        let _ = std::fs::remove_dir_all(&tmp);
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

    const FN_BUILD: &str =
        "#!/bin/sh\nprintf '\\000asm\\001\\000\\000\\000' > \"$OUT/function.wasm\"\necho ok\n";
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
        assert!(
            staged.join("_site_docs/index.html").exists(),
            "site content"
        );

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
        let listener = tokio::net::TcpListener::bind("172.31.0.1:3128")
            .await
            .unwrap();
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
            build_static: false,
            builder_hint: None,
            dockerfile: None,
            build_subdir: None,
            fetch_deadline: Duration::from_secs(20),
            seal: Some(make_seal(lease.tap.clone())),
        };
        std::fs::create_dir_all(&cfg.chroot_base).unwrap();

        let run = BuildVm::run("netseal", &cfg, &data.join("run")).await;
        net.release(lease).await;
        let run = run.expect("build VM run");
        assert_eq!(
            run.outcome,
            BuildOutcome::Completed,
            "build VM should complete"
        );

        let read = |name: &str| {
            build_output::read_capped(&output_img, name, 64)
                .ok()
                .flatten()
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .unwrap_or_else(|| "<missing>".into())
        };
        let (allow, block, direct, sealed) = (
            read("/allow"),
            read("/block"),
            read("/direct"),
            read("/sealed"),
        );
        println!("allow={allow} block={block} direct={direct} sealed={sealed}");

        assert_eq!(
            allow, "200",
            "allowlisted host must tunnel through the proxy"
        );
        assert_eq!(
            block, "403",
            "off-allowlist host must be refused by the proxy"
        );
        assert_eq!(
            direct, "down",
            "direct egress must be blocked by the firewall"
        );
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
        let Some(fx) = bun_pipeline_build("bunfix", 1, Workload::OfflineNoDep).await else {
            return;
        };
        let staged = &fx.staged;
        let store = &fx.store;
        let (project_id, build_id) = ("bunfix", 1u64);

        // Layered server artifact assembled into the deploy shape: NO flat tarball;
        // instead a content-addressed app erofs blob under _layers/.
        assert!(
            !staged.join("_servers/api.tar.gz").exists(),
            "no flat tarball in layered mode"
        );

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
        assert_eq!(
            mani["runtime"], "bun",
            "runtime language recorded for host injection"
        );
        let app_layer = mani["app_layer"].as_str().expect("app_layer recorded");
        assert!(
            app_layer.starts_with("sha256-") && app_layer.ends_with(".erofs"),
            "app_layer is a content-addressed erofs blob name: {app_layer}"
        );
        // The dumped + sha256-verified app blob is staged under _layers/.
        assert!(
            staged.join("_layers").join(app_layer).exists(),
            "app erofs blob staged"
        );
        assert_eq!(
            mani["app_digest"]
                .as_str()
                .map(|d| d.replace("sha256:", "sha256-") + ".erofs")
                .as_deref(),
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
        println!(
            "PASS: run_project_build drove bun.ext4 -> layered app erofs blob + launch manifest"
        );
    }

    /// The load-bearing proof for `docs/rootfs-cas-snapshot-durability.md`: a base-image
    /// redeploy must NOT brick a hibernated project. Boots a real microVM from the
    /// CONTENT-ADDRESSED rootfs path, hibernates it, then simulates a redeploy by minting a
    /// NEW rootfs blob alongside the old one (the old in-place rewrite would have poisoned the
    /// snapshot here), and restores the snapshot — which must still serve HTTP 200 against the
    /// RETAINED immutable blob. Finally asserts the GC is reference-counted (keeps a referenced
    /// blob; reaps an unreferenced one). Mirrors the managed-DB hibernate/restore harness.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/jkbob JKB_FC_RELEASE=/abs/.../release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/baselayers JKB_AGENT=/abs/jkbase-agent \
    ///       JKB_ROOTFS=/abs/base-rootfs.ext4 \
    ///       <test-bin> --ignored --nocapture cas_rootfs_survives_simulated_base_image_redeploy
    #[tokio::test]
    #[ignore = "needs KVM + root + baked bun.ext4 + JKB_ROOTFS; proves CAS rootfs durability across a redeploy"]
    async fn cas_rootfs_survives_simulated_base_image_redeploy() {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        let Some(fx) = bun_pipeline_build("casredeploy", 1, Workload::OfflineNoDep).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!("skip: set JKB_ROOTFS to the agent rootfs (tools/build-runtime-rootfs.sh)");
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Plain server (no managed DB, no data disk): layer plan + metadata image.
        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, &store_dir, false, true)
            .expect("compute layer plan for a plain server");
        let meta_img = fx.data.join("casredeploy-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            None,
            &meta_img,
        )
        .expect("build the metadata image");

        // Content-address the rootfs exactly as server startup does — this is blob "A".
        let cas_dir = fx.data.join("base-rootfs");
        let (rootfs_a, hash_a) =
            crate::rootfs_cas::place(&rootfs, &cas_dir).expect("CAS-place rootfs A");
        eprintln!(
            "[cas-e2e] rootfs A = {} ({}…)",
            rootfs_a.display(),
            &hash_a[..12]
        );

        // Point-to-point tap on its own /24 (clear of the other pipeline tests).
        let (tag, host_ip, guest_ip, guest_mac) = (
            "casredeploy",
            "172.28.0.1",
            "172.28.0.2",
            "AA:FC:00:00:28:02",
        );
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let cfg_a = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs_a.clone(),
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
            runtime_cgroup_parent: None,
        };
        let runtime_dir = fx.data.join("casredeploy-run");

        // --- Cold boot from the CAS rootfs path (proves base-rootfs/<hash>.ext4 boots + serves).
        let mut vm = VmInstance::start(tag, &cfg_a, &runtime_dir)
            .await
            .expect("VM should boot from the content-addressed rootfs path");
        let cold = poll_http_200(guest_ip, 80, Duration::from_secs(75)).await;
        eprintln!(
            "[cas-e2e] cold-boot from CAS rootfs → 200 = {}",
            cold.is_some()
        );
        assert!(
            cold.is_some(),
            "VM booted from the CAS rootfs must serve HTTP 200"
        );

        // --- Hibernate: the snapshot bakes rootfs path A.
        let snap_dir = fx.data.join("casredeploy-snap");
        let (snap, mem) = vm.hibernate(&snap_dir).await.expect("hibernate");

        // --- Simulate a base-image redeploy: a changed agent ⇒ different rootfs bytes ⇒ a NEW
        //     CAS blob "B" minted ALONGSIDE A. The OLD in-place rewrite would have clobbered the
        //     one fixed path and poisoned this snapshot; CAS keeps A immutable + retained.
        let tweaked = fx.data.join("rootfs-b.ext4");
        std::fs::copy(&rootfs, &tweaked).unwrap();
        {
            use std::io::Write;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(&tweaked)
                .unwrap();
            f.write_all(b"\0simulated-redeploy").unwrap();
        }
        let (_rootfs_b, hash_b) =
            crate::rootfs_cas::place(&tweaked, &cas_dir).expect("CAS-place rootfs B");
        assert_ne!(
            hash_a, hash_b,
            "a changed agent must mint a new rootfs hash"
        );
        assert!(
            rootfs_a.exists(),
            "the OLD rootfs blob MUST be retained so the snapshot can restore"
        );
        eprintln!(
            "[cas-e2e] redeploy minted rootfs B ({}…); A retained = {}",
            &hash_b[..12],
            rootfs_a.exists()
        );

        // --- Restore the snapshot AFTER the redeploy. Byte-correct against the retained immutable
        //     A → still serves 200. THIS is the durability the fix delivers.
        let mut woke = VmInstance::restore_from_snapshot(tag, &cfg_a, &runtime_dir, &snap, &mem)
            .await
            .expect("restore from snapshot against the retained CAS rootfs blob");
        let restored = poll_http_200(guest_ip, 80, Duration::from_secs(45)).await;
        eprintln!(
            "[cas-e2e] restore-after-redeploy → 200 = {}",
            restored.is_some()
        );
        let _ = woke.stop().await;
        assert!(
            restored.is_some(),
            "restore against the retained CAS blob must still serve 200 after a redeploy"
        );

        // --- GC is reference-counted: A is kept while referenced, reaped once it isn't (at which
        //     point a wake fails OPEN to a cold boot from B — see the decision unit test).
        let keep_both: std::collections::HashSet<String> =
            [hash_a.clone(), hash_b.clone()].into_iter().collect();
        let removed = crate::rootfs_cas::gc(&cas_dir, &keep_both).unwrap();
        assert!(
            removed.is_empty() && rootfs_a.exists(),
            "GC must keep a referenced blob"
        );
        let keep_b_only: std::collections::HashSet<String> = [hash_b].into_iter().collect();
        let removed = crate::rootfs_cas::gc(&cas_dir, &keep_b_only).unwrap();
        assert_eq!(
            removed,
            vec![hash_a],
            "GC must reap the now-unreferenced blob"
        );
        assert!(!rootfs_a.exists(), "the reaped blob must be gone");

        let _ = sh("ip", &["link", "del", &tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: CAS rootfs durability — boot from CAS path + restore against retained blob after a simulated redeploy + reference-counted GC"
        );
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
        /// Like `OfflineNoDep`, but the app talks to the co-located managed DB over
        /// loopback at runtime (no build network — the query is a runtime `fetch`).
        OfflineDatabase,
        /// Like `OfflineDatabase`, but the app FORWARDS the incoming request's
        /// `Authorization` header to the DB `/query` (P4 data-plane authz). Lets the test
        /// present / omit an end-user JWT per request and observe the rules engine's
        /// allow/deny — without baking any token into the image.
        AuthDatabase,
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
            matches!(
                self,
                Workload::NetworkedMonorepo | Workload::NetworkedSolidVite
            )
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
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
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
            // The managed-DB rung: a no-dep Bun server that talks to the co-located
            // RhypeDB over loopback (127.0.0.1:4200) at RUNTIME (the query is a `fetch`,
            // so no build network is needed). On each request it reads all `User` rows;
            // when none exist it seeds one ("alpha") and re-reads, echoing the round-trip
            // in the body. A 200 proves the DB booted in-VM, is reachable on loopback, and
            // create+read work. Until the DB has opened + bound (cold open) the `fetch`
            // throws and the handler returns 503 (caught) so the poll keeps retrying.
            // Seeding only-when-empty makes it idempotent against poll retries AND lets a
            // post-reboot request read "alpha" back WITHOUT re-seeding — proving persistence.
            Workload::OfflineDatabase => {
                write(
                    src.join("server/server.ts"),
                    r#"const port = Number(process.env.PORT) || 3000;
const DB = "http://127.0.0.1:4200/query";
async function q(query) {
  const r = await fetch(DB, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ query }) });
  if (!r.ok) throw new Error("db status " + r.status);
  return await r.json();
}
Bun.serve({ port, async fetch() {
  try {
    let res = await q("User");
    let objs = res.objects || [];
    if (objs.length === 0) {
      await q('User.create({ name: "alpha" })');
      res = await q("User");
      objs = res.objects || [];
    }
    const names = objs.map((o) => o.fields.name).sort();
    return new Response("users=" + names.join(",") + " count=" + objs.length + "\n");
  } catch (e) {
    return new Response("db-not-ready: " + e + "\n", { status: 503 });
  }
} });
console.log("listening on " + port);
"#,
                );
                write(
                    src.join("server/package.json"),
                    "{\n  \"name\": \"bunfix\",\n  \"module\": \"server.ts\",\n  \"packageManager\": \"bun@1.3.14\",\n  \"scripts\": { \"start\": \"bun run server.ts\" }\n}\n",
                );
            }
            // The P4 data-plane-authz rung: like OfflineDatabase, but the app FORWARDS the
            // incoming request's `Authorization` header to the DB `/query`. `GET /` reads all
            // `User`s (echoing `count=<n> status=<s>`); `GET /seed` creates one. So the test
            // presents / omits an end-user JWT per request and observes the rules engine:
            // authenticated ⇒ create/read allowed (count>0), anonymous ⇒ read filtered to 0 /
            // create refused (500). A failed fetch (DB cold-opening) ⇒ 503 so the poll retries.
            Workload::AuthDatabase => {
                write(
                    src.join("server/server.ts"),
                    r#"const port = Number(process.env.PORT) || 3000;
const DB = "http://127.0.0.1:4200/query";
async function q(query, auth) {
  const headers = { "content-type": "application/json" };
  if (auth) headers["authorization"] = auth;
  const r = await fetch(DB, { method: "POST", headers, body: JSON.stringify({ query }) });
  return { status: r.status, text: await r.text() };
}
Bun.serve({ port, async fetch(req) {
  const auth = req.headers.get("authorization") || "";
  const path = new URL(req.url).pathname;
  try {
    if (path === "/seed") {
      const c = await q('User.create({ name: "alpha" })', auth);
      return new Response("seed status=" + c.status + "\n");
    }
    const r = await q("User", auth);
    let n = 0;
    try { n = (JSON.parse(r.text).objects || []).length; } catch {}
    return new Response("count=" + n + " status=" + r.status + "\n");
  } catch (e) {
    return new Response("db-not-ready: " + e + "\n", { status: 503 });
  }
} });
console.log("listening on " + port);
"#,
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
                    eprintln!(
                        "skip: cannot bind egress proxy 172.31.0.1:3128 ({e}); run `sudo tools/setup-build-net.sh`"
                    );
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

        Some(BuildFixture {
            data,
            fc_release,
            kernel,
            store,
            staged,
        })
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
        networked_lang_build_try(project_id, redb, toolchain, src, t, build_id)
            .await
            .map(|r| r.expect("language server build should succeed"))
    }

    /// Like [`networked_lang_build`] but hands back the raw `run_project_build`
    /// RESULT instead of unwrapping it — so a NEGATIVE test (e.g. a monorepo build
    /// with the `context` widening OMITTED) can assert the build *fails*.
    async fn networked_lang_build_try(
        project_id: &str,
        redb: &str,
        toolchain: &str,
        src: &Path,
        t: BuildTuning,
        build_id: u64,
    ) -> Option<Result<BuildFixture>> {
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
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
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
                eprintln!(
                    "skip: cannot bind egress proxy 172.31.0.1:3128 ({e}); run `sudo tools/setup-build-net.sh`"
                );
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

        let staged = run_project_build(project_id.into(), build_id, tarbuf, deps.clone()).await;
        Some(staged.map(|staged| BuildFixture {
            data,
            fc_release,
            kernel,
            store,
            staged,
        }))
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
        let Some(fx) = node_express_build(1).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "nodep",
            "172.27.0.1",
            "172.27.0.2",
            "AA:FC:00:00:27:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered express/node server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: node(express) build -> layered collection -> node runtime layer -> HTTP 200 ({body:?})"
        );
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
        let Some(fx) = rust_tiny_http_build(1).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "rustp",
            "172.26.0.1",
            "172.26.0.2",
            "AA:FC:00:00:26:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered tiny_http/rust server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: rust(tiny_http) build -> layered collection -> rust runtime layer -> HTTP 200 ({body:?})"
        );
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
        let Some(fx) = python_build(1).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "pyp",
            "172.25.0.1",
            "172.25.0.2",
            "AA:FC:00:00:25:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered python server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: python(pip+six) build -> layered collection -> python runtime layer -> HTTP 200 ({body:?})"
        );
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
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "gop",
            "172.24.0.1",
            "172.24.0.2",
            "AA:FC:00:00:24:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the layered go server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: go(static+uuid) build -> layered collection -> go runtime layer -> HTTP 200 ({body:?})"
        );
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
        let Some(fx) = rust_assets_build(1).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "rusta", "172.25.0.1", "172.25.0.2", "AA:FC:00:00:25:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the rust server reading a baked asset via its entrypoint");
        assert_eq!(
            body, "asset-ok-seeded",
            "asset must ship (asset-ok) AND entrypoint must run (seeded)"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: rust assets+entrypoint build -> app layer with assets -> entrypoint exec -> HTTP 200 ({body:?})"
        );
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
        let Some(fx) = rust_native_lib_build(1).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx, &store_dir, &agent_bin, "rustn", "172.24.0.1", "172.24.0.2", "AA:FC:00:00:24:02",
        )
        .await
        .expect("agent should serve HTTP 200 from a rust server linking openssl via the per-app native-lib closure");
        assert_eq!(
            body, "native-ok OpenSSL",
            "openssl (libssl/libcrypto) must be shipped into the app layer and resolve at runtime"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: rust native-FFI (openssl) build -> app-layer /usr/lib closure -> runtime -> HTTP 200 ({body:?})"
        );
    }

    /// Build a minimal Trunk (Rust/WASM frontend) STATIC site through the pipeline:
    /// `cargo fetch` pulls the crates through the proxy, then the buildpack downloads the
    /// exact version-matched `wasm-bindgen` CLI release from github (allow-listed) onto
    /// PATH — it deliberately does NOT run `trunk build` during fetch (that would run
    /// untrusted build code with the network up). The offline `trunk build --release`
    /// then produces a `dist/` the host collects into the served site slot. Unlike the
    /// server fixtures this is a `[sites.*] build = "trunk"` target (`TargetKind::Static`)
    /// → `/out/static.tar.gz` → staged `_site_<name>/`.
    async fn trunk_static_build(build_id: u64) -> Option<BuildFixture> {
        let data = std::env::var("JKB_DATA").ok()?;
        let src = PathBuf::from(data).join("trunk-fixture-src");
        let _ = std::fs::remove_dir_all(&src);
        // A built site, not a server: the platform builds ./web with trunk and serves
        // the produced static tree as site `app` (→ staged `_site_app/`).
        write(
            src.join("jkbase.toml"),
            "[project]\nname = \"trunkfix\"\n\n[sites.app]\nsource = \"./web\"\nbuild = \"trunk\"\n",
        );
        // Canonical minimal trunk app: a wasm-bindgen crate + a Trunk.toml + an
        // index.html template carrying a marker we assert survives into the bundle.
        write(
            src.join("web/Cargo.toml"),
            "[package]\nname = \"trunkfix\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\nwasm-bindgen = \"=0.2.95\"\n",
        );
        write(src.join("web/Trunk.toml"), "[build]\n");
        write(
            src.join("web/index.html"),
            "<!DOCTYPE html>\n<html>\n<head>\n  <meta charset=\"utf-8\"/>\n  <link data-trunk rel=\"rust\"/>\n</head>\n<body><div id=\"app\">trunk-onbox-marker</div></body>\n</html>\n",
        );
        write(
            src.join("web/src/main.rs"),
            "use wasm_bindgen::prelude::*;\n\nfn main() {\n    // Touch wasm-bindgen so the dep is real and trunk runs wasm-bindgen on the output.\n    let _ = JsValue::from_str(\"trunk-onbox\");\n}\n",
        );
        networked_lang_build(
            // Short project id: the jailer socket path (chroot_base = `bj-<id>`) must stay
            // under SUN_LEN (108); a long repo data-dir leaves little budget.
            "trk",
            "onbox-trunk.redb",
            "trunk.ext4",
            &src,
            BuildTuning {
                vcpu: 4,
                guest_mem_mib: 2048,
                cgroup_mem_mib: 2560,
                cgroup_cpu_max: "400000 100000",
                // cargo + wasm build + wasm-bindgen + wasm-opt write a big target/ dir.
                scratch_mib: 2048,
                output_mib: 128,
                timeout_secs: 600,
                fetch_deadline_secs: 300,
            },
            build_id,
        )
        .await
    }

    /// Trunk static acceptance (build half): a `[sites.app] build = "trunk"` builds in a
    /// real build VM and the host collects the produced `dist/` into the served site slot
    /// `_site_app/`. Asserts the bundle landed — index.html (carrying the source marker)
    /// plus the trunk-emitted `.wasm` + `.js`. The SERVE half is the committed-static path
    /// (already proven by www/console), since `collect_static_site` lands content in the
    /// identical staged location a committed site is copied into.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… \
    ///       <test-bin> --ignored --nocapture trunk_static_pipeline_emits_site_tree
    #[tokio::test]
    #[ignore = "trunk static pipeline: needs KVM + root + trunk.ext4 + build bridge"]
    async fn trunk_static_pipeline_emits_site_tree() {
        let Some(fx) = trunk_static_build(1).await else {
            return;
        };
        let site = fx.staged.join("_site_app");
        let index = site.join("index.html");
        assert!(
            index.is_file(),
            "trunk build must land index.html in the served site slot {}",
            site.display()
        );
        let html = std::fs::read_to_string(&index).unwrap();
        assert!(
            html.contains("trunk-onbox-marker"),
            "served index.html must preserve the source template body; got:\n{html}"
        );
        // Trunk rewrites index.html to load the produced bundle: a hashed `.js` loader +
        // a `_bg.wasm`. Their presence proves trunk actually compiled (not just copied).
        let has_ext = |ext: &str| {
            std::fs::read_dir(&site)
                .unwrap()
                .filter_map(|e| e.ok())
                .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some(ext))
        };
        assert!(
            has_ext("wasm"),
            "trunk must emit a .wasm into the site slot"
        );
        assert!(
            has_ext("js"),
            "trunk must emit a .js loader into the site slot"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: trunk static build -> /static.tar.gz -> staged _site_app/ (index.html + wasm + js)"
        );
    }

    async fn sh(cmd: &str, args: &[&str]) -> std::io::Result<()> {
        let status = tokio::process::Command::new(cmd)
            .args(args)
            .status()
            .await?;
        if !status.success() {
            return Err(std::io::Error::other(format!(
                "{cmd} {args:?} failed ({status})"
            )));
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
        assert!(
            !plan.layer_paths.is_empty(),
            "a layered server must resolve >=1 erofs layer"
        );
        assert!(
            plan.runtime_layers.servers.contains_key("api"),
            "_layers.json maps the api server"
        );

        let meta_img = fx.data.join(format!("{tag}-metadata.ext4"));
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            None,
            &meta_img,
        )
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
            jkbase_orch::build_image::build_ro_ext4_from_dir(&rootfs_stage, &rootfs_img, 48)
                .unwrap();
            rootfs_img
        };

        // Point-to-point tap (clear of jkbuild0's 172.31.x).
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
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
            runtime_cgroup_parent: None,
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

    /// Function deploy e2e — the runtime DEPLOY + SERVE half end to end. A built
    /// `wasi:http` component (the committed fixture, so no build VM is needed) is staged
    /// as a function-only deployment, the host bakes the metadata image, and a **real
    /// `jkbase-agent` runtime VM** boots, loads it, and serves `GET /functions/hello` →
    /// HTTP 200 — with the injected secret readable and egress denied. Complements
    /// `function_build_smoke` (the BUILD half).
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/jkbob JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_AGENT=/abs/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    ///       <test-bin> --ignored --nocapture function_pipeline_to_http_200
    #[tokio::test]
    #[ignore = "function deploy e2e: needs KVM + root + musl agent"]
    async fn function_pipeline_to_http_200() {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        let Ok(data) = std::env::var("JKB_DATA") else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let data = PathBuf::from(data);
        let fc_release = std::env::var("JKB_FC_RELEASE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data.join("release-v1.15.1-x86_64"));
        let Ok(agent_bin) = std::env::var("JKB_AGENT").map(PathBuf::from) else {
            eprintln!("skip: set JKB_AGENT to the musl jkbase-agent binary");
            return;
        };
        if !agent_bin.exists() {
            eprintln!("skip: agent binary {} missing", agent_bin.display());
            return;
        }
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
        };
        if !kernel.exists() {
            eprintln!("skip: no kernel at {}", kernel.display());
            return;
        }

        // Stage a function-only deployment: the committed wasi:http component as
        // `_functions/hello.wasm`, with a sidecar injecting a secret (the runtime path the
        // server's inject_function_secrets produces).
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../jkbase-agent/tests/fixtures/echo-component.wasm");
        assert!(
            fixture.exists(),
            "missing component fixture {}",
            fixture.display()
        );
        let staged = data.join("fn-e2e-staged");
        let _ = std::fs::remove_dir_all(&staged);
        let funcs = staged.join("_functions");
        std::fs::create_dir_all(&funcs).unwrap();
        std::fs::copy(&fixture, funcs.join("hello.wasm")).unwrap();
        std::fs::write(
            funcs.join("hello.json"),
            r#"{"runtime":"wasi-http","env":{"DEMO_SECRET":"e2e-secret"}}"#,
        )
        .unwrap();

        // Empty layer plan (no servers) + metadata image (carries _functions).
        let plan =
            crate::layer_plan::compute_layer_plan(&staged, &data.join("baselayers"), false, true)
                .expect("compute layer plan");
        assert!(
            plan.layer_paths.is_empty(),
            "a function-only project has no erofs layers"
        );
        let meta_img = data.join("fn-e2e-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            None,
            &meta_img,
        )
        .expect("build the metadata image");

        // Minimal agent rootfs (vda): the musl agent as /sbin/init (no verity needed).
        let rootfs_stage = data.join("fn-e2e-vda-stage");
        let _ = std::fs::remove_dir_all(&rootfs_stage);
        for d in ["sbin", "proc", "sys", "dev", "tmp", "srv/www", "mnt/data"] {
            std::fs::create_dir_all(rootfs_stage.join(d)).unwrap();
        }
        std::fs::copy(&agent_bin, rootfs_stage.join("sbin/init")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let p = rootfs_stage.join("sbin/init");
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
        }
        let rootfs_img = data.join("fn-e2e-vda.ext4");
        jkbase_orch::build_image::build_ro_ext4_from_dir(&rootfs_stage, &rootfs_img, 48).unwrap();

        let (tag, host_ip, guest_ip, guest_mac) =
            ("fne2e", "172.23.0.1", "172.23.0.2", "AA:FC:00:00:23:02");
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel.clone(),
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
            runtime_cgroup_parent: None,
        };
        let runtime_dir = data.join(format!("{tag}-run"));
        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("runtime VM should start");

        // GET /functions/hello (poll_http_200 only hits `/`).
        let body = {
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let deadline = std::time::Instant::now() + Duration::from_secs(45);
            let mut out = None;
            while std::time::Instant::now() < deadline {
                if let Ok(mut s) = tokio::net::TcpStream::connect((guest_ip, 80u16)).await {
                    let _ = s
                        .write_all(b"GET /functions/hello HTTP/1.0\r\nHost: jkbase\r\n\r\n")
                        .await;
                    let mut buf = Vec::new();
                    if s.read_to_end(&mut buf).await.is_ok() {
                        let text = String::from_utf8_lossy(&buf);
                        if let Some((head, b)) = text.split_once("\r\n\r\n")
                            && head.lines().next().is_some_and(|l| l.contains(" 200 "))
                        {
                            out = Some(b.trim().to_string());
                            break;
                        }
                    }
                }
                tokio::time::sleep(Duration::from_millis(500)).await;
            }
            out
        };
        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;

        let body = body.expect("function should serve HTTP 200 at /functions/hello");
        eprintln!("function response:\n{body}");
        assert!(
            body.contains("hello from a wasi:http component"),
            "got: {body}"
        );
        assert!(
            body.contains("DEMO_SECRET=e2e-secret"),
            "injected secret must be readable: {body}"
        );
        assert!(
            body.contains("egress=DENIED"),
            "egress must be denied: {body}"
        );
    }

    /// Build a minimal DNS response: echo the query's header ID + question, append a single
    /// A record (`name → ip`) or set RCODE=NXDOMAIN when `ip` is `None`. Enough for the
    /// agent's hickory resolver (single A query, Ipv4Only). `query` is the raw UDP datagram.
    fn dns_reply(query: &[u8], ip: Option<std::net::Ipv4Addr>) -> Option<Vec<u8>> {
        if query.len() < 12 {
            return None;
        }
        // Walk the QNAME labels to find where the question ends (QTYPE+QCLASS follow).
        let mut i = 12usize;
        while i < query.len() {
            let len = query[i] as usize;
            if len == 0 {
                i += 1;
                break;
            }
            i += 1 + len;
        }
        let q_end = i + 4; // QTYPE(2) + QCLASS(2)
        if q_end > query.len() {
            return None;
        }
        let mut r = Vec::with_capacity(q_end + 16);
        r.extend_from_slice(&query[0..2]); // ID
        // Flags: QR=1, AA=1, RD copied from query, RA=0; RCODE 0 (or 3 = NXDOMAIN).
        let rd = query[2] & 0x01;
        let rcode: u8 = if ip.is_some() { 0 } else { 3 };
        r.push(0x84 | rd);
        r.push(rcode);
        r.extend_from_slice(&query[4..6]); // QDCOUNT (echo, =1)
        let ancount: u16 = if ip.is_some() { 1 } else { 0 };
        r.extend_from_slice(&ancount.to_be_bytes()); // ANCOUNT
        r.extend_from_slice(&[0, 0, 0, 0]); // NSCOUNT, ARCOUNT
        r.extend_from_slice(&query[12..q_end]); // echo the question
        if let Some(ip) = ip {
            r.extend_from_slice(&[0xc0, 0x0c]); // NAME pointer to the question
            r.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A, CLASS=IN
            r.extend_from_slice(&[0, 0, 0, 30]); // TTL=30
            r.extend_from_slice(&[0, 4]); // RDLENGTH
            r.extend_from_slice(&ip.octets());
        }
        Some(r)
    }

    /// G — the on-box EGRESS e2e. Boots a REAL agent VM whose function egress gate must
    /// resolve through a host-controlled resolver and reach (or refuse) host-controlled
    /// upstreams over the guest TAP — proving #7 (gate) + #9 (observe) end to end through the
    /// production runtime path, not just `decide()` in isolation. One boot, two functions
    /// (default + sandbox) sharing the header-driven egress-probe fixture; the test drives
    /// allow / sandbox-deny / platform-deny / DNS-rebind / ipv6-refuse by varying headers,
    /// then reads `/_jkbase/logs` and asserts the observe manifest recorded the verdicts.
    ///
    /// Self-contained control plane on the host side of the TAP:
    ///   * a tiny UDP DNS responder on 172.16.0.1:53 (the agent's PINNED resolver) maps
    ///     allow.test→9.9.9.9, platform.test→9.9.9.10, rebind.test→10.0.0.1;
    ///   * HTTP upstreams on 9.9.9.9:80 (allowed public) and 9.9.9.10:80 (a platform IP,
    ///     listed in `_platform.json` → must be denied), both host-owned via `lo` /32s.
    /// Plain HTTP only (a self-signed TLS upstream wouldn't pass webpki roots; the TLS
    /// construction mirrors default_send_request and is covered structurally).
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/jkbob JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_AGENT=/abs/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    ///       <test-bin> --ignored --nocapture function_egress_e2e
    #[tokio::test]
    #[ignore = "egress e2e: needs KVM + root + musl agent; binds 172.16.0.1:53 + 9.9.9.x"]
    async fn function_egress_e2e() {
        use jkbase_orch::vm::{VmConfig, VmInstance};
        use tokio::io::{AsyncReadExt, AsyncWriteExt};

        let Ok(data) = std::env::var("JKB_DATA").map(PathBuf::from) else {
            eprintln!("skip: set JKB_DATA");
            return;
        };
        let fc_release = std::env::var("JKB_FC_RELEASE")
            .map(PathBuf::from)
            .unwrap_or_else(|_| data.join("release-v1.15.1-x86_64"));
        let Ok(agent_bin) = std::env::var("JKB_AGENT").map(PathBuf::from) else {
            eprintln!("skip: set JKB_AGENT to the musl jkbase-agent binary");
            return;
        };
        if !agent_bin.exists() {
            eprintln!("skip: agent binary {} missing", agent_bin.display());
            return;
        }
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
        };
        if !kernel.exists() {
            eprintln!("skip: no kernel at {}", kernel.display());
            return;
        }

        // Stage two functions sharing the egress-probe fixture: one default, one sandbox.
        let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("../jkbase-agent/tests/fixtures/egress-probe.wasm");
        assert!(
            fixture.exists(),
            "missing egress-probe fixture {}",
            fixture.display()
        );
        let staged = data.join("egr-e2e-staged");
        let _ = std::fs::remove_dir_all(&staged);
        let funcs = staged.join("_functions");
        std::fs::create_dir_all(&funcs).unwrap();
        for (name, egress) in [
            ("probe_default", "\"default\""),
            ("probe_sandbox", "\"sandbox\""),
        ] {
            std::fs::copy(&fixture, funcs.join(format!("{name}.wasm"))).unwrap();
            std::fs::write(
                funcs.join(format!("{name}.json")),
                format!(r#"{{"runtime":"wasi-http","egress":{egress}}}"#),
            )
            .unwrap();
        }
        // Host-asserted platform facts (the PRODUCTION channel: a host param, NOT a tenant
        // file — build_metadata_image writes `_platform.json` from this, overriding anything
        // staged). 9.9.9.10 is a platform IP (must be denied); storage.test is the OWN host
        // (not exercised here — own-bucket is #10-A). A tenant-smuggled `_platform.json`
        // would be overwritten; we deliberately do NOT stage one.
        let platform = jkbase_common::config::PlatformEgress {
            storage_host: Some("storage.test".to_string()),
            platform_ips: vec!["9.9.9.10".to_string()],
        };

        let plan =
            crate::layer_plan::compute_layer_plan(&staged, &data.join("baselayers"), false, true)
                .expect("compute layer plan");
        let meta_img = data.join("egr-e2e-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &staged,
            &plan,
            &Default::default(),
            &platform,
            None,
            None,
            &meta_img,
        )
        .expect("build the metadata image");

        // Minimal agent rootfs (vda): the musl agent as /sbin/init.
        let rootfs_stage = data.join("egr-e2e-vda-stage");
        let _ = std::fs::remove_dir_all(&rootfs_stage);
        for d in [
            "sbin", "proc", "sys", "dev", "tmp", "srv/www", "mnt/data", "etc",
        ] {
            std::fs::create_dir_all(rootfs_stage.join(d)).unwrap();
        }
        std::fs::copy(&agent_bin, rootfs_stage.join("sbin/init")).unwrap();
        {
            use std::os::unix::fs::PermissionsExt;
            let p = rootfs_stage.join("sbin/init");
            let mut perm = std::fs::metadata(&p).unwrap().permissions();
            perm.set_mode(0o755);
            std::fs::set_permissions(&p, perm).unwrap();
        }
        let rootfs_img = data.join("egr-e2e-vda.ext4");
        jkbase_orch::build_image::build_ro_ext4_from_dir(&rootfs_stage, &rootfs_img, 48).unwrap();

        // Networking: the resolver is hardcoded to 172.16.0.1, so the gateway IS 172.16.0.1.
        let (host_ip, guest_ip, guest_mac) = ("172.16.0.1", "172.16.0.2", "AA:FC:00:00:16:02");
        let tap = "jkegre2e".to_string();
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();
        // Host owns the upstream IPs so a guest packet for them is delivered locally.
        for ip in ["9.9.9.9/32", "9.9.9.10/32"] {
            let _ = sh("ip", &["addr", "add", ip, "dev", "lo"]).await;
        }

        // Control plane on the host side of the TAP. Tasks abort when the test's runtime
        // shuts down at return; the TAP/lo teardown below also tears the bindings down.
        let dns = tokio::net::UdpSocket::bind((host_ip, 53u16))
            .await
            .expect("bind DNS :53");
        tokio::spawn(async move {
            let mut buf = [0u8; 1500];
            loop {
                let Ok((n, from)) = dns.recv_from(&mut buf).await else {
                    continue;
                };
                // Decode the QNAME (lowercased) for the map.
                let mut name = String::new();
                let mut i = 12usize;
                while i < n {
                    let len = buf[i] as usize;
                    if len == 0 {
                        break;
                    }
                    if !name.is_empty() {
                        name.push('.');
                    }
                    if i + 1 + len > n {
                        break;
                    }
                    name.push_str(&String::from_utf8_lossy(&buf[i + 1..i + 1 + len]));
                    i += 1 + len;
                }
                let name = name.to_ascii_lowercase();
                let ip = match name.as_str() {
                    "allow.test" => Some(std::net::Ipv4Addr::new(9, 9, 9, 9)),
                    "platform.test" => Some(std::net::Ipv4Addr::new(9, 9, 9, 10)),
                    "rebind.test" => Some(std::net::Ipv4Addr::new(10, 0, 0, 1)),
                    _ => None,
                };
                if let Some(reply) = dns_reply(&buf[..n], ip) {
                    let _ = dns.send_to(&reply, from).await;
                }
            }
        });

        for upstream in ["9.9.9.9", "9.9.9.10"] {
            let l = tokio::net::TcpListener::bind((upstream, 80u16))
                .await
                .unwrap_or_else(|e| panic!("bind upstream {upstream}:80: {e}"));
            tokio::spawn(async move {
                loop {
                    let Ok((mut s, _)) = l.accept().await else {
                        continue;
                    };
                    tokio::spawn(async move {
                        let mut b = [0u8; 1024];
                        let _ = s.read(&mut b).await;
                        let _ = s
                            .write_all(
                                b"HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\nupstream-ok",
                            )
                            .await;
                    });
                }
            });
        }

        let config = VmConfig {
            firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: kernel.clone(),
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
            runtime_cgroup_parent: None,
        };
        let runtime_dir = data.join("egr-e2e-run");
        let mut vm = VmInstance::start("egre2e", &config, &runtime_dir)
            .await
            .expect("runtime VM should start");

        // Drive one probe: GET /functions/{fn} with the egress-target headers; returns the
        // trimmed body (`RESULT:...`). Retries until the agent is up.
        async fn probe(
            guest_ip: &str,
            func: &str,
            authority: &str,
            scheme: &str,
        ) -> Option<String> {
            let deadline = std::time::Instant::now() + Duration::from_secs(45);
            while std::time::Instant::now() < deadline {
                if let Ok(mut s) = tokio::net::TcpStream::connect((guest_ip, 80u16)).await {
                    let req = format!(
                        "GET /functions/{func} HTTP/1.0\r\nHost: jkbase\r\nx-egress-scheme: {scheme}\r\nx-egress-authority: {authority}\r\nx-egress-path: /\r\n\r\n"
                    );
                    let _ = s.write_all(req.as_bytes()).await;
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

        let allow = probe(guest_ip, "probe_default", "allow.test", "http").await;
        let rebind = probe(guest_ip, "probe_default", "rebind.test", "http").await;
        let platform = probe(guest_ip, "probe_default", "platform.test", "http").await;
        let ipv6 = probe(guest_ip, "probe_default", "[::1]", "http").await;
        let sandbox = probe(guest_ip, "probe_sandbox", "allow.test", "http").await;

        // Pull the observe manifest (stream=="egress") before teardown.
        let logs = {
            let mut out = String::new();
            if let Ok(mut s) = tokio::net::TcpStream::connect((guest_ip, 80u16)).await {
                let _ = s
                    .write_all(b"GET /_jkbase/logs HTTP/1.0\r\nHost: jkbase\r\n\r\n")
                    .await;
                let mut buf = Vec::new();
                if s.read_to_end(&mut buf).await.is_ok() {
                    let text = String::from_utf8_lossy(&buf);
                    if let Some((_, body)) = text.split_once("\r\n\r\n") {
                        out = body.to_string();
                    }
                }
            }
            out
        };

        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;
        for ip in ["9.9.9.9/32", "9.9.9.10/32"] {
            let _ = sh("ip", &["addr", "del", ip, "dev", "lo"]).await;
        }

        eprintln!(
            "allow={allow:?}\nrebind={rebind:?}\nplatform={platform:?}\nipv6={ipv6:?}\nsandbox={sandbox:?}"
        );
        eprintln!("egress logs:\n{logs}");

        assert_eq!(
            allow.as_deref(),
            Some("RESULT:ALLOWED:200"),
            "default must reach an allowed public upstream"
        );
        assert_eq!(
            rebind.as_deref(),
            Some("RESULT:DENIED"),
            "a public name resolving to an internal IP must be denied (post-DNS)"
        );
        assert_eq!(
            platform.as_deref(),
            Some("RESULT:DENIED"),
            "a platform IP must be denied (Zone-2 by IP)"
        );
        assert_eq!(
            ipv6.as_deref(),
            Some("RESULT:DENIED"),
            "an IPv6 destination must be refused"
        );
        assert_eq!(
            sandbox.as_deref(),
            Some("RESULT:DENIED"),
            "a sandboxed function must not reach public"
        );

        // #9: the observe manifest recorded the verdicts, via the unified log pipe with the
        // reserved egress stream. Parse the events (the EgressEvent is JSON inside the
        // escaped `line` field) rather than substring-matching the escaped bytes.
        use jkbase_common::logs::{EgressEvent, Verdict};
        let parsed: serde_json::Value =
            serde_json::from_str(&logs).unwrap_or(serde_json::Value::Null);
        let events: Vec<EgressEvent> = parsed
            .get("lines")
            .and_then(|l| l.as_array())
            .map(|arr| {
                arr.iter()
                    .filter(|l| l.get("stream").and_then(|s| s.as_str()) == Some("egress"))
                    .filter_map(|l| l.get("line").and_then(|s| s.as_str()))
                    .filter_map(|s| serde_json::from_str::<EgressEvent>(s).ok())
                    .collect()
            })
            .unwrap_or_default();
        assert!(
            events
                .iter()
                .any(|e| e.verdict == Verdict::Allow && e.dest_host == "allow.test"),
            "an allow verdict must be recorded for allow.test: {logs}"
        );
        assert!(
            events.iter().any(|e| e.verdict == Verdict::DenySandbox),
            "the sandboxed function's deny must be recorded: {logs}"
        );
        assert!(
            events
                .iter()
                .any(|e| e.verdict == Verdict::DenyPlatform && e.dest_host == "platform.test"),
            "the platform-IP deny must be recorded: {logs}"
        );
        println!(
            "PASS: function_egress_e2e — allow/rebind/platform/ipv6/sandbox + observe manifest"
        );
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
        let Some(fx) = bun_pipeline_build("bunpipe", 1, Workload::OfflineNoDep).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "pipe",
            "172.30.0.1",
            "172.30.0.2",
            "AA:FC:00:00:30:02",
        )
        .await
        .expect("agent should proxy HTTP 200 from the layered bun server");
        assert_eq!(body, "ok");
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: build -> layered collection -> metadata image -> real agent runtime -> HTTP 200 ({body:?})"
        );
    }

    /// Managed-DB acceptance (P0.5) — the full managed-RhypeDB SERVE path end to end. A
    /// real Bun server is built through `run_project_build`; the host then stages the
    /// managed-DB sidecars (`_database.json` + a host-baked `_database/schema.rhype`)
    /// exactly as the deploy path (`run_inner` + `assemble_sidecars`) does, resolves the
    /// layer plan WITH a forced data disk, and bakes the metadata image. A **real
    /// `jkbase-agent` runtime VM** boots: the agent composes the `rhypedb:base` overlay,
    /// seeds the schema, starts `rhypedb-server` bound to 127.0.0.1:4200, and the app
    /// `fetch`es it (create + read) → HTTP 200 carrying the round-trip row. The DB then has
    /// to survive both halves of scale-to-zero: (1) **hibernate→wake** — Pause + full-mem
    /// snapshot + SIGKILL, then `restore_from_snapshot` — the restored guest must still serve
    /// the row (the real on-demand-wake path; depends on the snapshot-safe CPU template in
    /// jkbase-orch/src/vm.rs, without which a modern-host guest #GPs on XSAVE restore and
    /// panics ~1s into resume); and (2) a **hard-kill + cold reboot over the SAME data disk**
    /// — a fresh VM with no memory snapshot must replay the WAL and serve the row WITHOUT
    /// re-seeding, proving on-disk durability + crash recovery independent of the VMM
    /// snapshot path.
    ///
    /// JKB_ROOTFS is REQUIRED: the `rhypedb` + `base` shared layers carry dm-verity trees,
    /// so the in-guest agent must `veritysetup` them — only the prebuilt apko rootfs (agent
    /// as /sbin/init + cryptsetup) can; the hand-rolled minimal rootfs would (correctly)
    /// fail those layers closed.
    ///
    ///   cargo build -p jkbase-agent --release --target x86_64-unknown-linux-musl
    ///   OUT=.firecracker/base-rootfs-verity.ext4 \
    ///       AGENT_BIN=target/x86_64-unknown-linux-musl/release/jkbase-agent \
    ///       tools/build-runtime-rootfs.sh
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/.firecracker JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/.firecracker/baselayers \
    ///       JKB_AGENT=/abs/target/x86_64-unknown-linux-musl/release/jkbase-agent \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity.ext4 \
    ///       <test-bin> --ignored --nocapture managed_db_loopback_roundtrip_survives_hibernate_and_reboot
    #[tokio::test]
    #[ignore = "managed DB pipeline: needs KVM + root + bun.ext4 + baselayers + verity rootfs (JKB_ROOTFS)"]
    async fn managed_db_loopback_roundtrip_survives_hibernate_and_reboot() {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        let Some(fx) = bun_pipeline_build("bundb", 1, Workload::OfflineDatabase).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };

        // The verity-capable rootfs (agent as /sbin/init + veritysetup) — without it the
        // dm-verity'd rhypedb/base layers fail closed and the DB never starts.
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!(
                "skip: set JKB_ROOTFS to the verity-capable agent rootfs (tools/build-runtime-rootfs.sh)"
            );
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Stage the managed-DB sidecars into the built deployment, mirroring the deploy
        // path: `_database.json` (drives compute_layer_plan + the agent supervisor; the
        // admin token is NEVER in it) and the host-baked schema seeded into the DB meta
        // volume at boot. `run_project_build` is the BUILD half and ignores `[database]`;
        // this test exercises the SERVE half the deploy path hands the agent.
        std::fs::write(
            fx.staged.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.staged.join("_database")).unwrap();
        std::fs::write(
            fx.staged.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();

        // Host glue under test: resolve the layer plan WITH a forced data disk (a managed
        // DB MUST have persistent storage — the agent fails closed without /mnt/data) and
        // bake the metadata image (carrying `_database.json` + `_database/` + the device
        // map incl. `data_device`).
        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, &store_dir, true, true)
            .expect("compute layer plan with a managed DB + data disk");
        assert!(
            plan.runtime_layers.database.is_some(),
            "_layers.json must map the managed DB overlay (rhypedb:base)"
        );
        assert!(
            plan.runtime_layers.data_device.is_some(),
            "a managed DB forces a data-disk device"
        );

        let meta_img = fx.data.join("dbpipe-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            None,
            &meta_img,
        )
        .expect("build the metadata image");

        // A formatted ext4 data disk attached LAST (after the layers): the agent mounts it
        // at /mnt/data and the DB persists to /mnt/data/volumes/rhypedb-data.
        let data_disk = fx.data.join("dbpipe-data.ext4");
        let _ = std::fs::remove_file(&data_disk);
        sh("truncate", &["-s", "1G", data_disk.to_str().unwrap()])
            .await
            .unwrap();
        sh("mkfs.ext4", &["-F", "-q", data_disk.to_str().unwrap()])
            .await
            .unwrap();

        // Point-to-point tap (clear of jkbuild0's 172.31.x and the other pipeline tests).
        let (tag, host_ip, guest_ip, guest_mac) =
            ("dbpipe", "172.27.0.1", "172.27.0.2", "AA:FC:00:00:27:02");
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(meta_img.clone()),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: Some(data_disk.clone()),
            vcpu_count: 2,
            mem_size_mib: 1024,
            tap_device: Some(tap.clone()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let runtime_dir = fx.data.join("dbpipe-run");

        // --- Cold boot: the DB opens its data dir, binds loopback; the app round-trips it.
        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("runtime VM with a managed DB should start");
        // First request seeds "alpha" + reads it back; 503 (caught) until the DB has opened
        // + bound (cold open), so poll generously.
        let cold = poll_http_200(guest_ip, 80, Duration::from_secs(75)).await;
        eprintln!("[db-e2e] cold-boot body = {cold:?}");

        // --- Hibernate (Pause + full-mem snapshot + SIGKILL) then restore: jkbase's actual
        //     scale-to-zero path. The restored guest resumes from the memory snapshot and
        //     must still serve the row. (Depends on the snapshot-safe CPU template in
        //     jkbase-orch/src/vm.rs — without it, a modern-host guest #GPs in
        //     restore_fpregs_from_fpstate and panics ~1s into resume.)
        let wake = if cold.as_deref() == Some("users=alpha count=1") {
            let snap_dir = fx.data.join("dbpipe-snap");
            let (snap, mem) = vm
                .hibernate(&snap_dir)
                .await
                .expect("hibernate the managed-DB VM");
            let mut woke =
                VmInstance::restore_from_snapshot(tag, &config, &runtime_dir, &snap, &mem)
                    .await
                    .expect("restore the managed-DB VM from snapshot");
            let body = poll_http_200(guest_ip, 80, Duration::from_secs(45)).await;
            eprintln!("[db-e2e] hibernate-wake body = {body:?}");
            let _ = woke.stop().await; // hard-kill the restored VM for the cold reboot below
            body
        } else {
            let _ = vm.stop().await;
            None
        };

        // --- Cold reboot over the SAME data disk: a FRESH VM (no memory snapshot) must
        //     replay the WAL and serve the row WITHOUT re-seeding. Proves on-disk durability
        //     + crash recovery, independent of the VMM snapshot path.
        let restart = if wake.as_deref() == Some("users=alpha count=1") {
            let runtime_dir2 = fx.data.join("dbpipe-run2");
            let mut vm2 = VmInstance::start(tag, &config, &runtime_dir2)
                .await
                .expect("fresh runtime VM should reboot over the persistent data disk");
            let body = poll_http_200(guest_ip, 80, Duration::from_secs(60)).await;
            eprintln!("[db-e2e] cold-reboot body = {body:?}");
            let _ = vm2.stop().await;
            body
        } else {
            None
        };

        let _ = sh("ip", &["link", "del", &tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);

        assert_eq!(
            cold.as_deref(),
            Some("users=alpha count=1"),
            "cold boot: the app must create + read back a row over loopback (DB reachable at 127.0.0.1:4200)"
        );
        assert_eq!(
            wake.as_deref(),
            Some("users=alpha count=1"),
            "after hibernate→wake (scale-to-zero) the restored DB must still serve the row"
        );
        assert_eq!(
            restart.as_deref(),
            Some("users=alpha count=1"),
            "after a hard-kill + cold reboot the row must still be served (on-disk persistence + DB WAL recovery)"
        );
        println!(
            "PASS: managed DB boots in-VM -> loopback round-trip -> HTTP 200 -> survives hibernate→wake AND hard-kill + cold reboot ({cold:?})"
        );
    }

    /// The P4 data-plane-authz end-to-end proof: a co-located managed DB booted with a baked
    /// `rules.rhype` + the project's PUBLIC JWKS (delivered over the reserved `_db_reach.json`
    /// channel, exactly as the deploy path bakes `DbReachFacts.jwks`) ENFORCES default-deny rules
    /// against a REAL end-user JWT. The app forwards each request's `Authorization` to the DB
    /// `/query`, so presenting / omitting a token minted by the jkbase issuer's `jose` (the exact
    /// format `auth.jkbase.app` emits and the engine's `rhypedb-authz` verifies) drives the engine:
    ///   - authenticated ⇒ create ALLOWED (200) + read returns the row (count=1)
    ///   - anonymous     ⇒ read filtered to 0, create REFUSED (500)
    /// This exercises the WHOLE jkbase-side chain under test: agent seeds `rules.rhype` + `jwks.json`
    /// into the meta volume + sets `RHYPEDB_RULES`/`RHYPEDB_AUTH_JWKS` → the engine verifies the
    /// EdDSA JWT offline against the baked JWKS → the rules gate the query. Rules-OFF is already the
    /// `managed_db_loopback_*` test above (this is the opt-in that closes the doors).
    #[tokio::test]
    #[ignore = "P4 rules e2e: needs KVM + root + bun.ext4 + baselayers + verity rootfs (JKB_ROOTFS)"]
    async fn managed_db_rules_enforced_e2e() {
        use jkbase_common::config::DbReachFacts;
        use jkbase_control::jose::{Claims, Jwks, SigningKeypair};
        use jkbase_orch::vm::{VmConfig, VmInstance};

        let Some(fx) = bun_pipeline_build("rulesdb", 1, Workload::AuthDatabase).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!(
                "skip: set JKB_ROOTFS to the verity-capable agent rootfs (tools/build-runtime-rootfs.sh)"
            );
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Mint a real end-user token + its JWKS with the jkbase issuer's jose — byte-identical to
        // what `auth.jkbase.app` emits and what the engine's rhypedb-authz verifies (kid ties them).
        let kp = SigningKeypair::from_seed("rulesproj.0", [7u8; 32]);
        let jwks_json = serde_json::to_string(&Jwks::new(vec![kp.jwk()])).unwrap();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let token = kp
            .sign(&Claims {
                iss: "https://auth.jkbase.app".into(),
                sub: "user-1".into(),
                aud: "rulesproj".into(),
                iat: now,
                exp: now + 3600,
                jti: "e2e-1".into(),
                claims: None,
            })
            .unwrap();
        let bearer = format!("Bearer {token}");

        // Stage the managed-DB sidecars: schema + a default-deny rule that admits only an
        // authenticated principal, and `_database.json` opting into rules.
        std::fs::write(
            fx.staged.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":"rules.rhype"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.staged.join("_database")).unwrap();
        std::fs::write(
            fx.staged.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();
        std::fs::write(
            fx.staged.join("_database/rules.rhype"),
            "match User {\n  allow read, create: if request.auth != null;\n}\n",
        )
        .unwrap();

        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, &store_dir, true, true)
            .expect("compute layer plan with a managed DB + data disk");
        assert!(
            plan.runtime_layers.database.is_some(),
            "_layers.json must map the managed DB overlay (rhypedb:base)"
        );

        // The host-authored JWKS rides the reserved channel (`_db_reach.json`), exactly as the
        // deploy path bakes it; the agent seeds it to the meta volume + points RHYPEDB_AUTH_JWKS at
        // it. splice/admin are unused here but are non-forgeable placeholders (co-located tier).
        let db_reach = DbReachFacts {
            splice_secret: "e2e-splice".into(),
            admin_token: "e2e-admin".into(),
            dedicated: false,
            jwks: Some(jwks_json),
        };
        let meta_img = fx.data.join("rulesdb-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            Some(&db_reach),
            &meta_img,
        )
        .expect("build the metadata image (rules + JWKS)");

        let data_disk = fx.data.join("rulesdb-data.ext4");
        let _ = std::fs::remove_file(&data_disk);
        sh("truncate", &["-s", "1G", data_disk.to_str().unwrap()])
            .await
            .unwrap();
        sh("mkfs.ext4", &["-F", "-q", data_disk.to_str().unwrap()])
            .await
            .unwrap();

        let (tag, host_ip, guest_ip, guest_mac) =
            ("rulesdb", "172.28.0.1", "172.28.0.2", "AA:FC:00:00:28:02");
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh("ip", &["addr", "add", &format!("{host_ip}/24"), "dev", &tap])
            .await
            .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(meta_img.clone()),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: Some(data_disk.clone()),
            vcpu_count: 2,
            mem_size_mib: 1024,
            tap_device: Some(tap.clone()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let runtime_dir = fx.data.join("rulesdb-run");

        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("runtime VM with a rules-on managed DB should start");

        // Readiness: an unauthenticated GET / returns 200 once the DB is up (a denied read is a
        // FILTERED 200, not an error) — so this doubles as the first deny observation. If rules or
        // the JWKS failed to load the engine would exit (fail-closed) → the DB never binds → the app
        // stays 503 → this times out to None and the assert below fails loud.
        let ready = poll_http_200(guest_ip, 80, Duration::from_secs(90)).await;
        eprintln!("[rules-e2e] ready (anon read) = {ready:?}");

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        async fn get(
            client: &reqwest::Client,
            ip: &str,
            path: &str,
            bearer: Option<&str>,
        ) -> Option<String> {
            let mut rb = client.get(format!("http://{ip}:80{path}"));
            if let Some(b) = bearer {
                rb = rb.header("authorization", b);
            }
            let r = rb.send().await.ok()?;
            r.text().await.ok()
        }

        // Authenticated: create ALLOWED (200) + read returns the row (count=1).
        let seed_auth = get(&client, guest_ip, "/seed", Some(&bearer)).await;
        eprintln!("[rules-e2e] seed WITH token = {seed_auth:?}");
        let read_auth = get(&client, guest_ip, "/", Some(&bearer)).await;
        eprintln!("[rules-e2e] read WITH token = {read_auth:?}");
        // Anonymous: read filtered to zero, create REFUSED (500).
        let read_anon = get(&client, guest_ip, "/", None).await;
        eprintln!("[rules-e2e] read WITHOUT token = {read_anon:?}");
        let seed_anon = get(&client, guest_ip, "/seed", None).await;
        eprintln!("[rules-e2e] seed WITHOUT token = {seed_anon:?}");

        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);

        assert!(
            ready.is_some(),
            "DB must boot + the app must serve (a rules-on engine that couldn't load rules/JWKS \
             exits fail-closed and never binds)"
        );
        assert_eq!(
            seed_auth.as_deref(),
            Some("seed status=200\n"),
            "authenticated create must be ALLOWED by the rule (request.auth != null)"
        );
        assert_eq!(
            read_auth.as_deref(),
            Some("count=1 status=200\n"),
            "authenticated read must see the created row"
        );
        assert_eq!(
            read_anon.as_deref(),
            Some("count=0 status=200\n"),
            "anonymous read must be DEFAULT-DENIED (the row filtered out) — the whole point of P4"
        );
        assert_eq!(
            seed_anon.as_deref(),
            Some("seed status=500\n"),
            "anonymous create must be REFUSED (a denied write fails loud)"
        );
        println!(
            "PASS: P4 rules enforced in-VM — authenticated create/read ALLOWED, anonymous read \
             filtered + write refused (baked rules.rhype + reserved-channel JWKS)"
        );
    }

    /// The managed-DB REACH-PLANE end-to-end proof: a genuine `@rhypedb/client` round-trip
    /// travels the WHOLE external path — real `jkbase db proxy` sidecar → TLS `:443`-style
    /// edge (ALPN demux + preamble auth + tls-exporter channel-bind + wake) → agent
    /// `/_jkbase/db` splice → loopback rhypedb TCP wire (`:4201`) — and back. Unlike the
    /// loopback test above (which proves the DB boots + persists), this proves the reach
    /// plane is *usable* from outside the VM with the real client wire.
    ///
    /// It THEN proves managed-DB BACKUP + RESTORE end-to-end: standing in for the server-side
    /// executor, it pulls a snapshot off the agent's `/_jkbase/db/backup` (which authorizes the
    /// loopback `/admin/backup/stream` with the injected admin token) into the platform
    /// `BackupStore` + validates it, MUTATES the DB (adds `beta`), then pushes the snapshot to
    /// `/_jkbase/db/restore` (agent untars in-guest + respawns rhypedb via `RHYPEDB_RESTORE_FROM`)
    /// and observes the DB REVERT to the backup state (`alpha` only) — proving admin-token
    /// injection, the pull, tar validation, and a real in-guest restore respawn.
    ///
    /// It orchestrates the REAL binaries as subprocesses (like the other on-box tests locate
    /// JKB_AGENT/JKB_ROOTFS): the built `jkbase` CLI (`JKB_CLI`) and a tiny helper that links
    /// the real `rhypedb-client` (`RHYPEDB_PROBE`, from `tools/rhypedb-probe`). The host side
    /// stands up a `DbIngress` with a self-signed `*.db.local` cert; the sidecar trusts it via
    /// `--ca-file`, and `testproj.db.local` is pointed at 127.0.0.1 in `/etc/hosts` (the test
    /// runs as root) so the real CLI dials + SNI-pins exactly as in production.
    ///
    ///   cargo build -p jkbase-cli
    ///   cargo build --manifest-path tools/rhypedb-probe/Cargo.toml --release
    ///   cargo build -p jkbase-agent --release --target x86_64-unknown-linux-musl
    ///   OUT=.firecracker/base-rootfs-verity.ext4 AGENT_BIN=…/jkbase-agent tools/build-runtime-rootfs.sh
    ///   cargo test -p jkbase-server --no-run
    ///   sudo env JKB_DATA=/abs/.firecracker JKB_FC_RELEASE=/abs/.firecracker/release-v1.15.1-x86_64 \
    ///       JKB_BASELAYERS=/abs/.firecracker/baselayers JKB_AGENT=/abs/…/jkbase-agent \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity.ext4 \
    ///       JKB_CLI=/abs/target/debug/jkbase \
    ///       RHYPEDB_PROBE=/abs/tools/rhypedb-probe/target/release/rhypedb-probe \
    ///       <test-bin> --ignored --nocapture managed_db_reach_plane_e2e
    #[tokio::test]
    #[ignore = "reach-plane e2e: KVM+root + baselayers + JKB_ROOTFS + JKB_CLI + RHYPEDB_PROBE"]
    async fn managed_db_reach_plane_e2e() {
        use jkbase_orch::vm::{VmConfig, VmInstance};
        use std::future::Future;
        use std::pin::Pin;

        // Real binaries this e2e drives as subprocesses.
        let Ok(cli) = std::env::var("JKB_CLI").map(PathBuf::from) else {
            eprintln!("skip: set JKB_CLI to the built `jkbase` binary");
            return;
        };
        let Ok(probe) = std::env::var("RHYPEDB_PROBE").map(PathBuf::from) else {
            eprintln!("skip: set RHYPEDB_PROBE to tools/rhypedb-probe's built binary");
            return;
        };
        if !cli.exists() || !probe.exists() {
            eprintln!("skip: JKB_CLI/RHYPEDB_PROBE binary missing");
            return;
        }

        let Some(fx) = bun_pipeline_build("dbreach", 1, Workload::OfflineDatabase).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!("skip: set JKB_ROOTFS to the verity-capable agent rootfs");
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Stage the managed DB, mirroring the deploy path (see the loopback test) …
        std::fs::write(
            fx.staged.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.staged.join("_database")).unwrap();
        std::fs::write(
            fx.staged.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();

        // The reach-plane credentials this e2e uses. In production the akid/secret are an
        // owner-held DB key (minted via the control API) and the splice secret is host-minted
        // per deploy; here the host edge harness's auth callback stands in for the control
        // store, and we bake the SAME splice secret the agent will verify.
        let akid = "JKBDreach0e2e000000f";
        let owner_secret = "jkbd_reach-e2e-owner-secret-value";
        let splice_secret = "reach-e2e-splice-secret-0123456789abcdef";
        // The per-deploy rhypedb admin token — baked into _db_reach.json so the agent injects it
        // as RHYPEDB_ADMIN_TOKEN AND uses it to authorize the loopback /admin/backup/stream pull.
        let admin_token = "jkba_reach-e2e-admin-token-0123456789abcdef";

        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, &store_dir, true, true)
            .expect("compute layer plan with a managed DB + data disk");
        assert!(plan.runtime_layers.database.is_some());
        assert!(plan.runtime_layers.data_device.is_some());

        let meta_img = fx.data.join("dbreach-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            // [R3] Host-authored reach facts: the per-deploy splice secret the agent's
            // `/_jkbase/db` handler will require on the backend upgrade.
            Some(&jkbase_common::config::DbReachFacts {
                splice_secret: splice_secret.to_string(),
                admin_token: admin_token.to_string(),
                dedicated: false,
                jwks: None,
            }),
            &meta_img,
        )
        .expect("build the metadata image");

        let data_disk = fx.data.join("dbreach-data.ext4");
        let _ = std::fs::remove_file(&data_disk);
        sh("truncate", &["-s", "1G", data_disk.to_str().unwrap()])
            .await
            .unwrap();
        sh("mkfs.ext4", &["-F", "-q", data_disk.to_str().unwrap()])
            .await
            .unwrap();

        // Point-to-point tap on a subnet clear of the other pipeline tests.
        let (tag, host_ip, guest_ip, guest_mac) =
            ("dbreach", "172.29.0.1", "172.29.0.2", "AA:FC:00:00:29:02");
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh(
            "ip",
            &["addr", "add", &format!("{host_ip}/24"), "dev", &tap],
        )
        .await
        .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(meta_img.clone()),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: Some(data_disk.clone()),
            vcpu_count: 2,
            mem_size_mib: 1024,
            tap_device: Some(tap.clone()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let runtime_dir = fx.data.join("dbreach-run");
        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("runtime VM with a managed DB should start");

        // ---- Host-side reach-plane EDGE: a self-signed `*.db.local` cert + a DbIngress ----
        let sni_host = "testproj.db.local";
        let ck = rcgen::generate_simple_self_signed(vec![sni_host.to_string()]).unwrap();
        let ca_path = fx.data.join("dbreach-edge-ca.pem");
        std::fs::write(&ca_path, ck.cert.pem()).unwrap();
        let cert_der =
            tokio_rustls::rustls::pki_types::CertificateDer::from(ck.cert.der().to_vec());
        let key_der =
            tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(ck.key_pair.serialize_der());
        let provider = std::sync::Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
        let mut scfg = tokio_rustls::rustls::ServerConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key_der.into())
            .unwrap();
        scfg.alpn_protocols = vec![b"jkbase-db".to_vec(), b"http/1.1".to_vec()];
        let acceptor = tokio_rustls::TlsAcceptor::from(std::sync::Arc::new(scfg));

        // Auth callback: stands in for the control store's DB-key lookup + [R1] SNI==project
        // + owner re-bind, returning the baked splice secret on success.
        let (akid_c, secret_c, splice_c) = (
            akid.to_string(),
            owner_secret.to_string(),
            splice_secret.to_string(),
        );
        let auth: jkbase_proxy::DbAuthCallback =
            std::sync::Arc::new(move |a: &str, s: &str, claimed: &str| {
                if a == akid_c && s == secret_c && claimed == "testproj" {
                    Some(jkbase_proxy::DbAuthOk {
                        project_id: "testproj".to_string(),
                        splice_secret: splice_c.clone(),
                        tenant_id: Some("testtenant".to_string()),
                        warm_vm_max: jkbase_control::store::DEFAULT_TENANT_QUOTA.warm_vm_max,
                        warm_relay_max: jkbase_control::store::DEFAULT_TENANT_QUOTA.warm_relay_max,
                    })
                } else {
                    None
                }
            });
        // Wake: the VM is already up, so return its IP immediately.
        let guest_ip_owned = guest_ip.to_string();
        let wake: jkbase_proxy::WakeCallback = std::sync::Arc::new(
            move |_pid: String| -> Pin<
                Box<dyn Future<Output = Result<String, jkbase_proxy::WakeError>> + Send>,
            > {
                let ip = guest_ip_owned.clone();
                Box::pin(async move { Ok(ip) })
            },
        );
        let ingress = std::sync::Arc::new(jkbase_proxy::db_ingress::DbIngress {
            domain: std::sync::Arc::new("local".to_string()),
            auth,
            wake,
            registry: jkbase_proxy::db_relay::DbRelayRegistry::new(),
            activity: None,
            backend_port: 80,
            global: std::sync::Arc::new(tokio::sync::Semaphore::new(1024)),
            preauth: std::sync::Arc::new(tokio::sync::Semaphore::new(256)),
            per_ip: jkbase_proxy::db_ingress::PerIpLimiter::new(32),
            per_project_max: 64,
        });
        let edge_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let edge_port = edge_listener.local_addr().unwrap().port();
        let edge_task = tokio::spawn(async move {
            loop {
                let Ok((sock, peer)) = edge_listener.accept().await else {
                    continue;
                };
                let acceptor = acceptor.clone();
                let ingress = ingress.clone();
                tokio::spawn(async move {
                    if let Ok(tls) = acceptor.accept(sock).await
                        && tls.get_ref().1.alpn_protocol() == Some(b"jkbase-db".as_ref())
                    {
                        ingress.handle(tls, peer.ip()).await;
                    }
                });
            }
        });

        // ---- Point `testproj.db.local` at the loopback edge so the REAL CLI dials + pins it.
        let hosts_line = format!("127.0.0.1 {sni_host} # jkbase-dbreach-e2e\n");
        let hosts_before = std::fs::read_to_string("/etc/hosts").unwrap_or_default();
        {
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open("/etc/hosts")
                .expect("append /etc/hosts (test must run as root)");
            use std::io::Write as _;
            f.write_all(hosts_line.as_bytes()).unwrap();
        }

        // ---- The REAL sidecar in front of the edge, trusting the self-signed cert.
        let local_port = {
            let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            l.local_addr().unwrap().port()
        };
        let sidecar_log = fx.data.join("dbreach-sidecar.log");
        let mut sidecar = tokio::process::Command::new(&cli)
            .args([
                "db",
                "proxy",
                "--db-host",
                sni_host,
                "--port",
                &edge_port.to_string(),
                "--listen",
                &format!("127.0.0.1:{local_port}"),
                "--access-key-id",
                akid,
                "--secret",
                owner_secret,
                "--ca-file",
                ca_path.to_str().unwrap(),
            ])
            .stdout(std::fs::File::create(&sidecar_log).unwrap())
            .stderr(std::fs::File::create(fx.data.join("dbreach-sidecar.err")).unwrap())
            .kill_on_drop(true)
            .spawn()
            .expect("spawn jkbase db proxy");

        // ---- Drive the REAL rhypedb-client through the whole path. On a fresh DB the probe
        //      creates `alpha` then reads it back — proving create AND read travel the reach
        //      plane. Retry to cover cold-boot / sidecar-warmup; each attempt is sequential so
        //      the create-if-empty can't double-insert.
        let mut probe_out = String::new();
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        while std::time::Instant::now() < deadline {
            if let Ok(out) = tokio::process::Command::new(&probe)
                .arg(format!("127.0.0.1:{local_port}"))
                .output()
                .await
            {
                let stdout = String::from_utf8_lossy(&out.stdout).trim().to_string();
                if out.status.success() && stdout.contains("count=1") {
                    probe_out = stdout;
                    break;
                }
                eprintln!(
                    "[reach-e2e] probe not ready: status={} out={:?} err={:?}",
                    out.status,
                    stdout,
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            tokio::time::sleep(Duration::from_millis(1500)).await;
        }

        // ---- Managed-DB BACKUP + RESTORE over the direct host<->agent channels ----
        // Only meaningful once the alpha round-trip proved the DB is up + reachable. The test
        // stands in for the server-side executor: connect the agent's eth0 `/_jkbase/db/backup`
        // + `/_jkbase/db/restore` with the baked splice secret and drive the real
        // BackupStore/validate path. A full round-trip proves: admin-token injection into
        // rhypedb, the pull of `/admin/backup/stream`, tar validation, and a real restore
        // (mutate the DB, restore the earlier snapshot, observe it revert).
        let mut backup_summary = String::new();
        let mut after_beta = String::new();
        let mut after_restore = String::new();
        if probe_out == "users=alpha count=1" {
            let backups =
                crate::db_backup_store::BackupStore::new(&fx.data.join("dbreach-backups"));
            let backup_id = "bkp_0000000000001_e2eaaaaa";
            let local = format!("127.0.0.1:{local_port}");

            // BACKUP: pull the tar off the agent, then validate + commit it.
            match async {
                let mut up = crate::connect_agent_db_upgrade(
                    guest_ip,
                    "/_jkbase/db/backup",
                    splice_secret,
                    "jkbase-db-backup",
                )
                .await?;
                let staged = backups
                    .stage("testproj", backup_id, &mut up, 1 << 30)
                    .await?;
                let summary = backups.validate(&staged).await?;
                backups.commit(staged).await?;
                Ok::<String, anyhow::Error>(summary)
            }
            .await
            {
                Ok(s) => backup_summary = s,
                Err(e) => eprintln!("[backup-e2e] backup failed: {e:#}"),
            }

            // Mutate: add `beta`, so the DB (alpha+beta) now differs from the backup (alpha).
            if let Ok(out) = tokio::process::Command::new(&probe)
                .args([local.as_str(), "create", "beta"])
                .output()
                .await
            {
                after_beta = String::from_utf8_lossy(&out.stdout).trim().to_string();
            }

            // RESTORE the earlier snapshot; the agent untars it in-guest + respawns rhypedb.
            let restore_status = async {
                use tokio::io::{AsyncReadExt, AsyncWriteExt};
                let mut tar = backups.open_read("testproj", backup_id).await?;
                let mut up = crate::connect_agent_db_upgrade(
                    guest_ip,
                    "/_jkbase/db/restore",
                    splice_secret,
                    "jkbase-db-restore",
                )
                .await?;
                tokio::io::copy(&mut tar, &mut up).await?;
                up.shutdown().await?;
                let mut status = String::new();
                up.read_to_string(&mut status).await?;
                Ok::<String, anyhow::Error>(status.trim().to_string())
            }
            .await;

            match restore_status {
                Ok(status) => {
                    // After restore, list the DB (retry across the DB respawn/warmup window).
                    let deadline = std::time::Instant::now() + Duration::from_secs(60);
                    while std::time::Instant::now() < deadline {
                        if let Ok(out) = tokio::process::Command::new(&probe)
                            .args([local.as_str(), "list"])
                            .output()
                            .await
                        {
                            let o = String::from_utf8_lossy(&out.stdout).trim().to_string();
                            if out.status.success() && o.starts_with("users=") {
                                after_restore = format!("restore={status} {o}");
                                break;
                            }
                        }
                        tokio::time::sleep(Duration::from_millis(1500)).await;
                    }
                }
                Err(e) => eprintln!("[backup-e2e] restore failed: {e:#}"),
            }
        }

        // ---- Cleanup BEFORE asserting (mirror the loopback test) so a failed assert can't
        //      leak the tap / /etc/hosts line / child processes.
        let _ = sidecar.start_kill();
        let _ = sidecar.wait().await;
        edge_task.abort();
        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;
        std::fs::write("/etc/hosts", hosts_before).ok(); // restore exactly
        // Surface the sidecar's own output on failure (it's the most opaque hop).
        if probe_out.is_empty()
            && let Ok(err) = std::fs::read_to_string(fx.data.join("dbreach-sidecar.err"))
        {
            eprintln!("[reach-e2e] sidecar stderr:\n{}", err.trim());
        }
        let _ = std::fs::remove_dir_all(&fx.staged);

        assert_eq!(
            probe_out, "users=alpha count=1",
            "the real rhypedb-client must create+read a row through the FULL reach plane \
             (sidecar -> TLS edge -> agent /_jkbase/db splice -> loopback rhypedb :4201)"
        );
        println!("PASS: reach-plane e2e — real @rhypedb/client round-trip through {probe_out:?}");

        // ---- Backup + restore assertions (the DB was alive for the whole phase above) ----
        assert!(
            backup_summary.contains("ssts="),
            "backup must pull a VALID tar off the agent (admin-token inject + /admin/backup/stream \
             + host validation); got {backup_summary:?}"
        );
        assert_eq!(
            after_beta, "users=alpha,beta count=2",
            "mutation before restore must add `beta` (DB now differs from the backup)"
        );
        assert_eq!(
            after_restore, "restore=ok users=alpha count=1",
            "restore must push the snapshot to the agent, respawn rhypedb from it, and REVERT the \
             DB to the backup state (alpha only, beta gone)"
        );
        println!(
            "PASS: backup+restore e2e — {backup_summary:?}; post-mutation {after_beta:?}; \
             post-restore {after_restore:?}"
        );
    }

    /// The app→DB **in-guest leg** (P2 §7.6) end-to-end against real infra: a REAL host DB gateway
    /// (`db_gateway`) in front of a REAL **DbOnly** DB VM. This is the DEDICATED counterpart to the
    /// co-located loopback test — the DB runs ALONE in a `DbOnly` VM (no app), reachable only
    /// host-mediated. A client connection to the gateway (standing in for a dedicated app VM's
    /// in-guest loopback proxy) is authenticated by its **source IP** → project → the **host-held**
    /// splice secret, `wake`d, and spliced to the DB VM agent's `/_jkbase/db` with
    /// `x-jkbase-db-port: 4200` → the loopback rhypedb HTTP plane — and a create+read row
    /// round-trips back. Proves: source-IP auth, the `DbReachFacts` split (DbOnly image), the
    /// host-set port header on the splice, and the whole gateway spine against a live engine.
    ///
    /// The wire plane (`:4201`) uses the identical splice minus the port-header value and is proven
    /// by `managed_db_reach_plane_e2e` (edge → `/_jkbase/db` → `:4201`); here we prove the HTTP
    /// plane (`:4200`) end-to-end through the NEW gateway. Same prerequisites as the loopback test.
    ///
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity.ext4 \
    ///       <test-bin> --ignored --nocapture managed_db_dedicated_leg_e2e
    #[tokio::test]
    #[ignore = "dedicated app→DB leg e2e: needs KVM + root + baselayers + verity rootfs (JKB_ROOTFS)"]
    async fn managed_db_dedicated_leg_e2e() {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        // Reuse the proven build fixture (the built app is unused — a DbOnly image drops it — but
        // this gives us the baselayers store + a valid deployment tree the plan machinery expects).
        let Some(fx) = bun_pipeline_build("dedleg", 1, Workload::OfflineDatabase).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!("skip: set JKB_ROOTFS to the verity-capable agent rootfs");
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Stage the managed DB (schema only; the DbOnly image carries no app). `tier=dedicated`
        // documents intent — the DbOnly image build below is what actually excludes the app.
        std::fs::write(
            fx.staged.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null,"tier":"dedicated"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.staged.join("_database")).unwrap();
        std::fs::write(
            fx.staged.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();

        let splice_secret = "dedleg-splice-secret-0123456789abcdef";
        let admin_token = "jkba_dedleg-admin-token-0123456789abcdef";

        // DbOnly image: rhypedb overlay + `_database` + a forced data disk, NO app servers.
        let plan = crate::layer_plan::compute_layer_plan_with(
            &fx.staged,
            &store_dir,
            true,
            true,
            crate::layer_plan::ImageContent::DbOnly,
        )
        .expect("compute DbOnly layer plan");
        assert!(
            plan.runtime_layers.database.is_some(),
            "DbOnly image must map the rhypedb overlay"
        );
        assert!(
            plan.runtime_layers.data_device.is_some(),
            "a managed DB forces a data-disk device"
        );

        let meta_img = fx.data.join("dedleg-metadata.ext4");
        crate::layer_plan::build_metadata_image_with(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            // The DB VM's OWN image: the splice secret its `/_jkbase/db` will require, and NEVER
            // `dedicated` (it is the DB, not an app that proxies to one).
            Some(&jkbase_common::config::DbReachFacts {
                splice_secret: splice_secret.to_string(),
                admin_token: admin_token.to_string(),
                dedicated: false,
                jwks: None,
            }),
            &meta_img,
            crate::layer_plan::ImageContent::DbOnly,
        )
        .expect("build the DbOnly metadata image");

        let data_disk = fx.data.join("dedleg-data.ext4");
        let _ = std::fs::remove_file(&data_disk);
        sh("truncate", &["-s", "1G", data_disk.to_str().unwrap()])
            .await
            .unwrap();
        sh("mkfs.ext4", &["-F", "-q", data_disk.to_str().unwrap()])
            .await
            .unwrap();

        // Point-to-point tap on a subnet clear of the other pipeline tests (26.x).
        let (tag, host_ip, guest_ip, guest_mac) =
            ("dedleg", "172.26.0.1", "172.26.0.2", "AA:FC:00:00:26:02");
        let tap = format!("jk{tag}");
        let _ = sh("ip", &["link", "del", &tap]).await;
        sh("ip", &["tuntap", "add", "dev", &tap, "mode", "tap"])
            .await
            .unwrap();
        sh("ip", &["addr", "add", &format!("{host_ip}/24"), "dev", &tap])
            .await
            .unwrap();
        sh("ip", &["link", "set", &tap, "up"]).await.unwrap();

        let config = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(meta_img.clone()),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: Some(data_disk.clone()),
            vcpu_count: 1,
            mem_size_mib: 1024,
            tap_device: Some(tap.clone()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let runtime_dir = fx.data.join("dedleg-run");
        let mut vm = VmInstance::start(tag, &config, &runtime_dir)
            .await
            .expect("DbOnly DB VM should start");

        // ---- The REAL host DB gateway ---------------------------------------------------------
        // A temp control store maps the client's source IP (127.0.0.1 — we drive the gateway from
        // the host loopback, standing in for the app VM's proxy) → project "ded", and holds the
        // splice secret the gateway presents to the DB agent. `wake` returns the (already-booted)
        // DB VM's IP; the agent backend port is the guest `:80`.
        let gw_store = Store::open(&fx.data.join("dedleg-gw-store.redb")).expect("open gw store");
        gw_store
            .save_vm_allocation(&jkbase_control::store::VmAllocation {
                project_id: "ded".to_string(),
                ip: "127.0.0.1".to_string(),
                tap_device: tap.clone(),
                mac: guest_mac.to_string(),
                host_id: String::new(),
                placement_epoch: 0,
            })
            .unwrap();
        gw_store.set_db_splice_secret("ded", splice_secret).unwrap();
        let guest_ip_owned = guest_ip.to_string();
        let wake: jkbase_proxy::WakeCallback = std::sync::Arc::new(move |_pid: String| {
            let ip = guest_ip_owned.clone();
            Box::pin(async move { Ok(ip) })
        });
        let registry = jkbase_proxy::db_relay::DbRelayRegistry::new();
        // Fixed high test ports (bind on loopback only). A bind failure disables the leg → the
        // round-trip below fails clearly.
        let (gw_http, gw_wire) = (34230u16, 34231u16);
        tokio::spawn(crate::db_gateway::serve_on(
            gw_store,
            wake,
            registry,
            String::new(), // host_id: the test alloc uses empty host_id → matches
            "127.0.0.1",
            gw_http,
            gw_wire,
            80,
        ));

        // ---- Drive a create+read through the leg (mirrors the OfflineDatabase app handler) -----
        // Each request: client → gateway (source-IP auth + wake + agent upgrade w/ port 4200) →
        // splice → loopback rhypedb :4200 → back. Poll while the DB cold-opens/binds (the gateway
        // drops connections until rhypedb is up, so a request errors → retry).
        let base = format!("http://127.0.0.1:{gw_http}/query");
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .unwrap();
        async fn q(client: &reqwest::Client, base: &str, query: &str) -> Option<serde_json::Value> {
            let r = client
                .post(base)
                .json(&serde_json::json!({ "query": query }))
                .send()
                .await
                .ok()?;
            if !r.status().is_success() {
                return None;
            }
            r.json::<serde_json::Value>().await.ok()
        }
        let mut roundtrip: Option<String> = None;
        let deadline = std::time::Instant::now() + Duration::from_secs(90);
        while std::time::Instant::now() < deadline {
            // Read; if empty, seed alpha and re-read (idempotent against retries).
            if let Some(mut res) = q(&client, &base, "User").await {
                let mut objs = res
                    .get("objects")
                    .and_then(|o| o.as_array())
                    .cloned()
                    .unwrap_or_default();
                if objs.is_empty() {
                    q(&client, &base, r#"User.create({ name: "alpha" })"#).await;
                    res = q(&client, &base, "User").await.unwrap_or(res);
                    objs = res
                        .get("objects")
                        .and_then(|o| o.as_array())
                        .cloned()
                        .unwrap_or_default();
                }
                if !objs.is_empty() {
                    let mut names: Vec<String> = objs
                        .iter()
                        .filter_map(|o| o.get("fields")?.get("name")?.as_str().map(String::from))
                        .collect();
                    names.sort();
                    roundtrip = Some(format!("users={} count={}", names.join(","), objs.len()));
                    break;
                }
            }
            tokio::time::sleep(Duration::from_millis(500)).await;
        }
        eprintln!("[dedleg-e2e] leg round-trip = {roundtrip:?}");

        let _ = vm.stop().await;
        let _ = sh("ip", &["link", "del", &tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);

        assert_eq!(
            roundtrip.as_deref(),
            Some("users=alpha count=1"),
            "the app→DB leg must create+read a row THROUGH the host gateway \
             (source-IP auth -> wake -> agent /_jkbase/db x-jkbase-db-port:4200 -> loopback rhypedb)"
        );
        println!(
            "PASS: dedicated app→DB leg e2e — create+read round-trip through the REAL host gateway \
             + DbOnly DB VM ({roundtrip:?})"
        );
    }

    /// The app→DB leg FULL-STACK proof: TWO real VMs — a dedicated **app VM** (AppNoDb, its agent
    /// running the in-guest loopback proxy) and its sibling **DB VM** (DbOnly) — plus the REAL host
    /// gateway bound on the well-known bridge gateway IP (`172.16.0.1:4230/4231`). The bun app,
    /// UNCHANGED, `fetch`es `127.0.0.1:4200` exactly as co-located; its agent proxies that to the
    /// gateway, which source-IP-authenticates the app VM → project → wakes + splices to the DB VM.
    /// A `curl` of the app VM's `:80` returns the create+read row — proving the WHOLE leg incl. the
    /// two pieces the isolated `managed_db_dedicated_leg_e2e` doesn't: the agent's loopback proxy
    /// and the `DbReachFacts.dedicated` flag actually driving it.
    ///
    /// The app VM's tap host IP IS `172.16.0.1` (= `DB_GATEWAY_IP`) so the in-guest proxy reaches
    /// the gateway; the DB VM sits on a separate /24 the host also reaches. No `jkbr0` needed.
    ///
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       JKB_ROOTFS=/abs/.firecracker/base-rootfs-verity.ext4 \
    ///       <test-bin> --ignored --nocapture managed_db_dedicated_leg_fullstack_e2e
    #[tokio::test]
    #[ignore = "dedicated app→DB FULL-STACK leg e2e (2 VMs): needs KVM + root + bun.ext4 + baselayers + verity rootfs"]
    async fn managed_db_dedicated_leg_fullstack_e2e() {
        use jkbase_orch::vm::{VmConfig, VmInstance};

        let Some(fx) = bun_pipeline_build("dedfs", 1, Workload::OfflineDatabase).await else {
            return;
        };
        let Some((store_dir, _agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let Ok(rootfs) = std::env::var("JKB_ROOTFS").map(PathBuf::from) else {
            eprintln!("skip: set JKB_ROOTFS to the verity-capable agent rootfs");
            return;
        };
        assert!(rootfs.exists(), "JKB_ROOTFS {} missing", rootfs.display());

        // Stage the managed DB (dedicated tier).
        std::fs::write(
            fx.staged.join("_database.json"),
            r#"{"engine":"rhypedb","schema":"schema.rhype","rules":null,"tier":"dedicated"}"#,
        )
        .unwrap();
        std::fs::create_dir_all(fx.staged.join("_database")).unwrap();
        std::fs::write(
            fx.staged.join("_database/schema.rhype"),
            "type User {\n    name: String\n}\n",
        )
        .unwrap();

        let splice_secret = "dedfs-splice-secret-0123456789abcdef";
        let admin_token = "jkba_dedfs-admin-token-0123456789abcdef";

        // --- Build BOTH per-VM images from the one tree, exactly as the deploy path does. ---
        // App VM = AppNoDb (app layers + `_db_reach.json{dedicated:true}`, NO `_database`); it must
        // NOT force a data disk (the DB lives in the sibling VM).
        let app_plan = crate::layer_plan::compute_layer_plan_with(
            &fx.staged,
            &store_dir,
            false,
            true,
            crate::layer_plan::ImageContent::AppNoDb,
        )
        .expect("compute AppNoDb layer plan");
        assert!(
            app_plan.runtime_layers.database.is_none(),
            "AppNoDb must NOT carry the rhypedb overlay (else it co-locates a 2nd DB)"
        );
        let app_meta = fx.data.join("dedfs-app-metadata.ext4");
        crate::layer_plan::build_metadata_image_with(
            &fx.staged,
            &app_plan,
            &Default::default(),
            &Default::default(),
            None,
            Some(&jkbase_common::config::DbReachFacts {
                splice_secret: splice_secret.to_string(),
                admin_token: String::new(),
                dedicated: true, // ← drives the agent's in-guest loopback proxy
                jwks: None,
            }),
            &app_meta,
            crate::layer_plan::ImageContent::AppNoDb,
        )
        .expect("build the AppNoDb metadata image");

        // DB VM = DbOnly (rhypedb overlay + `_database` + forced data disk, no app).
        let db_plan = crate::layer_plan::compute_layer_plan_with(
            &fx.staged,
            &store_dir,
            true,
            true,
            crate::layer_plan::ImageContent::DbOnly,
        )
        .expect("compute DbOnly layer plan");
        assert!(db_plan.runtime_layers.database.is_some());
        let db_meta = fx.data.join("dedfs-db-metadata.ext4");
        crate::layer_plan::build_metadata_image_with(
            &fx.staged,
            &db_plan,
            &Default::default(),
            &Default::default(),
            None,
            Some(&jkbase_common::config::DbReachFacts {
                splice_secret: splice_secret.to_string(),
                admin_token: admin_token.to_string(),
                dedicated: false,
                jwks: None,
            }),
            &db_meta,
            crate::layer_plan::ImageContent::DbOnly,
        )
        .expect("build the DbOnly metadata image");

        let db_disk = fx.data.join("dedfs-db-data.ext4");
        let _ = std::fs::remove_file(&db_disk);
        sh("truncate", &["-s", "1G", db_disk.to_str().unwrap()])
            .await
            .unwrap();
        sh("mkfs.ext4", &["-F", "-q", db_disk.to_str().unwrap()])
            .await
            .unwrap();

        // --- Two point-to-point taps. The APP tap host IP is 172.16.0.1 (= DB_GATEWAY_IP) so the
        //     in-guest proxy reaches the gateway; the DB tap is a separate /24 (no route overlap).
        let app_tap = "jkdedfsapp".to_string();
        let db_tap = "jkdedfsdb".to_string();
        for (t, host, _g) in [
            (&app_tap, "172.16.0.1", "172.16.0.2"),
            (&db_tap, "172.21.0.1", "172.21.0.2"),
        ] {
            let _ = sh("ip", &["link", "del", t]).await;
            sh("ip", &["tuntap", "add", "dev", t, "mode", "tap"])
                .await
                .unwrap();
            sh("ip", &["addr", "add", &format!("{host}/24"), "dev", t])
                .await
                .unwrap();
            sh("ip", &["link", "set", t, "up"]).await.unwrap();
        }
        let (app_guest, db_guest) = ("172.16.0.2", "172.21.0.2");

        // --- The REAL host gateway on the well-known IP + ports (production `serve`). ---
        let gw_store = Store::open(&fx.data.join("dedfs-gw-store.redb")).expect("open gw store");
        gw_store
            .save_vm_allocation(&jkbase_control::store::VmAllocation {
                project_id: "ded".to_string(),
                ip: app_guest.to_string(), // the app VM's (source-guard-pinned) source IP
                tap_device: app_tap.clone(),
                mac: "AA:FC:00:00:16:02".to_string(),
                host_id: String::new(),
                placement_epoch: 0,
            })
            .unwrap();
        gw_store.set_db_splice_secret("ded", splice_secret).unwrap();
        let db_guest_owned = db_guest.to_string();
        let wake: jkbase_proxy::WakeCallback = std::sync::Arc::new(move |_pid: String| {
            let ip = db_guest_owned.clone();
            Box::pin(async move { Ok(ip) })
        });
        let registry = jkbase_proxy::db_relay::DbRelayRegistry::new();
        // host_id empty → the test alloc (also empty) matches. Binds 172.16.0.1:4230/4231.
        tokio::spawn(crate::db_gateway::serve(gw_store, wake, registry, String::new()));

        // --- Boot the DB VM first (the app's very first query must find it up). ---
        let db_cfg = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(db_meta.clone()),
            layer_paths: db_plan.layer_paths.clone(),
            data_disk_path: Some(db_disk.clone()),
            vcpu_count: 1,
            mem_size_mib: 1024,
            tap_device: Some(db_tap.clone()),
            guest_mac: Some("AA:FC:00:00:15:02".to_string()),
            guest_ip: Some(db_guest.to_string()),
            gateway_ip: Some("172.21.0.1".to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let mut db_vm = VmInstance::start("dedfsdb", &db_cfg, &fx.data.join("dedfs-db-run"))
            .await
            .expect("DbOnly DB VM should start");

        // --- Boot the app VM (AppNoDb; its agent starts the loopback proxy → the gateway). ---
        let app_cfg = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path: rootfs.clone(),
            metadata_image_path: Some(app_meta.clone()),
            layer_paths: app_plan.layer_paths.clone(),
            data_disk_path: None,
            vcpu_count: 1,
            mem_size_mib: 1024,
            tap_device: Some(app_tap.clone()),
            guest_mac: Some("AA:FC:00:00:16:02".to_string()),
            guest_ip: Some(app_guest.to_string()),
            gateway_ip: Some("172.16.0.1".to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: None,
        };
        let mut app_vm = VmInstance::start("dedfsapp", &app_cfg, &fx.data.join("dedfs-app-run"))
            .await
            .expect("AppNoDb app VM should start");

        // curl the app's :80 — it fetches 127.0.0.1:4200 → agent loopback proxy → gateway → DB VM.
        let body = poll_http_200(app_guest, 80, Duration::from_secs(120)).await;
        eprintln!("[dedfs-e2e] app-over-leg body = {body:?}");

        let _ = app_vm.stop().await;
        let _ = db_vm.stop().await;
        let _ = sh("ip", &["link", "del", &app_tap]).await;
        let _ = sh("ip", &["link", "del", &db_tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);

        assert_eq!(
            body.as_deref(),
            Some("users=alpha count=1"),
            "the UNCHANGED app must create+read a row over 127.0.0.1:4200 → in-guest proxy → host \
             gateway → sibling DB VM (the full app→DB leg)"
        );
        println!(
            "PASS: dedicated app→DB FULL-STACK leg e2e — unchanged app queried its sibling DB VM \
             over the in-guest loopback proxy + host gateway ({body:?})"
        );
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
        let Some(fx) = bun_pipeline_build("bunnet", 1, Workload::NetworkedMonorepo).await else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };

        // Lean-layer proof: the built app erofs carries the PRODUCTION deps (ms, debug)
        // but NOT the dev dep (typescript) — pruned out of the runtime layer.
        assert_app_layer_pruned(&fx.staged).await;

        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "netpipe",
            "172.28.0.1",
            "172.28.0.2",
            "AA:FC:00:00:28:02",
        )
        .await
        .expect("agent should serve 200 using the proxy-fetched `ms` dependency");
        assert_eq!(
            body, "ok 1m",
            "response uses ms(60000)=1m — proves `ms` was fetched through the egress proxy and runs"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: networked bun install (ms+debug via proxy, sealed) + lean prune (no typescript) -> layered runtime -> HTTP 200 ({body:?})"
        );
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
        sh(
            "mount",
            &[
                "-t",
                "erofs",
                "-o",
                "ro,loop",
                app_erofs.to_str().unwrap(),
                mnt.to_str().unwrap(),
            ],
        )
        .await
        .expect("mount app erofs");
        let nm = mnt.join("app/node_modules");
        let present = |p: &str| nm.join(p).exists();
        let (has_ms, has_debug, has_ts) = (present("ms"), present("debug"), present("typescript"));
        let _ = sh("umount", &[mnt.to_str().unwrap()]).await;
        let _ = std::fs::remove_dir_all(&mnt);
        assert!(has_ms, "production dep `ms` must be in the app layer");
        assert!(has_debug, "production dep `debug` must be in the app layer");
        assert!(
            !has_ts,
            "dev dep `typescript` must be PRUNED from the app layer"
        );
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
        println!(
            "PASS: networked Solid/Vite `bun run build` delegated to node -> dist/ in the app layer"
        );
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
        sh(
            "mount",
            &[
                "-t",
                "erofs",
                "-o",
                "ro,loop",
                app_erofs.to_str().unwrap(),
                mnt.to_str().unwrap(),
            ],
        )
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
            eprintln!(
                "skip: {}/dockerfile.ext4 not baked (run `tools/dev toolchains`)",
                toolchain_dir.display()
            );
            return None;
        }
        let kernel = {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
        };

        // Fixture: ONE server built from a user Dockerfile. The image serves "ok" on
        // $PORT (the platform routing contract). builder="dockerfile" → image/self.
        let src = data.join(format!("df-fixture-src-{project_id}"));
        let _ = std::fs::remove_dir_all(&src);
        write(
            src.join("jkbase.toml"),
            "[project]\nname = \"dffix\"\n[servers.api]\nbuilder = \"dockerfile\"\ndockerfile = \"./svc/Dockerfile\"\nport = 8080\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n",
        );
        // FROM (pull via 3129) + RUN (crun) + COPY + a relative CMD (resolved via the
        // image's own PATH — exercises the image/self non-clobbering env path).
        write(
            src.join("svc/Dockerfile"),
            "FROM python:3.12-alpine\nRUN echo built-in-vm > /built.txt\nCOPY server.py /server.py\nCMD [\"python3\", \"/server.py\"]\n",
        );
        write(
            src.join("svc/server.py"),
            "import os, http.server, socketserver\nport = int(os.environ.get('PORT', '8080'))\nclass H(http.server.BaseHTTPRequestHandler):\n    def do_GET(self):\n        self.send_response(200); self.send_header('Content-Length', '2'); self.end_headers(); self.wfile.write(b'ok')\n    def log_message(self, *a):\n        pass\nsocketserver.TCPServer(('0.0.0.0', port), H).serve_forever()\n",
        );

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
                Err(e) => {
                    eprintln!("skip: cannot bind 172.31.0.1:3128 ({e}); run `sudo tools/dev net`");
                    return None;
                }
            };
            let any = match tokio::net::TcpListener::bind("172.31.0.1:3129").await {
                Ok(l) => l,
                Err(e) => {
                    eprintln!("skip: cannot bind 172.31.0.1:3129 ({e}); run `sudo tools/dev net`");
                    return None;
                }
            };
            tokio::spawn(crate::egress::serve(
                allow,
                Arc::new(crate::egress::EgressConfig::with_default_allowlist()),
            ));
            tokio::spawn(crate::egress::serve(
                any,
                Arc::new(crate::egress::EgressConfig::allow_any_public()),
            ));
            Some(Arc::new(BuildNet::new(
                "jkbuild0".into(),
                "172.31.0.1".into(),
                3128,
                Some(3129),
                100_000,
                8,
            )))
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
        Some(BuildFixture {
            data,
            fc_release,
            kernel,
            store,
            staged,
        })
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
        assert_eq!(
            layers.len(),
            1,
            "a dockerfile build is ONE self-contained app layer"
        );
        let mani: serde_json::Value =
            serde_json::from_slice(&std::fs::read(staged.join("_servers/api.json")).unwrap())
                .unwrap();
        assert_eq!(
            mani["runtime"], "image/self",
            "dockerfile server runtime must be image/self"
        );
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
        let Some(fx) = dockerfile_pipeline_build("dfpipe", 1).await else {
            return;
        };
        assert_image_self_single_layer(&fx.staged).await;
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "dfpipe",
            "172.27.0.1",
            "172.27.0.2",
            "AA:FC:00:00:27:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the dockerfile-built image/self server");
        assert_eq!(
            body, "ok",
            "the image's own python entrypoint serves 'ok' on $PORT"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: builder=dockerfile (buildah FROM via 3129 public-any + RUN via crun) -> single image/self erofs layer -> runtime -> HTTP 200 ({body:?})"
        );
    }

    /// Write a Rust WORKSPACE fixture into `src`: a virtual-workspace root, a `common`
    /// library crate, and a `server` bin crate that path-depends on `../common` AND on
    /// the registry crate `tiny_http`. The served HTTP body comes from the SIBLING
    /// crate (`common::body()`), so a 200 proves `common` actually linked — not just
    /// that the build ran. `with_context` picks the manifest: `true` adds
    /// `context = "."` (mount the whole workspace → `../common` resolves); `false`
    /// omits it (only `server/` is mounted → the sibling is absent → the build fails).
    fn write_rust_monorepo(src: &Path, with_context: bool) {
        let _ = std::fs::remove_dir_all(src);
        write(
            src.join("Cargo.toml"),
            "[workspace]\nmembers = [\"common\", \"server\"]\nresolver = \"2\"\n",
        );
        write(
            src.join("common/Cargo.toml"),
            "[package]\nname = \"common\"\nversion = \"0.1.0\"\nedition = \"2021\"\n",
        );
        write(
            src.join("common/src/lib.rs"),
            "/// The HTTP body lives in the SIBLING crate — a 200 proves it linked.\npub fn body() -> &'static str {\n    \"ok\\n\"\n}\n",
        );
        write(
            src.join("server/Cargo.toml"),
            "[package]\nname = \"server\"\nversion = \"0.1.0\"\nedition = \"2021\"\n\n[dependencies]\ncommon = { path = \"../common\" }\ntiny_http = \"0.12\"\n",
        );
        write(
            src.join("server/src/main.rs"),
            "fn main() {\n    let port: u16 = std::env::var(\"PORT\").ok().and_then(|p| p.parse().ok()).unwrap_or(3000);\n    let server = tiny_http::Server::http((\"0.0.0.0\", port)).unwrap();\n    println!(\"listening on {port}\");\n    for req in server.incoming_requests() {\n        // The body is the SIBLING crate's — proves `../common` resolved + linked.\n        let _ = req.respond(tiny_http::Response::from_string(common::body()));\n    }\n}\n",
        );
        // `context = "."` mounts the whole workspace at /src and builds in `server`;
        // omitting it mounts only `server/`, so `../common` points outside the mount.
        let context_line = if with_context {
            "context = \".\"\n"
        } else {
            ""
        };
        write(
            src.join("jkbase.toml"),
            &format!(
                "[project]\nname = \"monofix\"\n\n[servers.api]\nsource = \"server\"\n{context_line}language = \"rust\"\nport = 3000\n\n[routes.\"/\"]\nservice = \"server\"\nname = \"api\"\n"
            ),
        );
    }

    /// E2E for the monorepo build `context`: a Rust workspace whose `[servers.api]`
    /// crate path-depends on an in-repo SIBLING crate. With `context = "."` the whole
    /// workspace is mounted at `/src`, the build runs in `build_subdir = "server"`, the
    /// `../common` path-dep RESOLVES, and the layered runtime serves the sibling's
    /// bytes → HTTP 200. This is the exact case that FAILS today (only `server/` is
    /// mounted) — see `monorepo_without_context_fails` for the negative control.
    ///
    ///   cargo test -p jkbase-server --no-run
    ///   sudo tools/setup-build-net.sh   # once
    ///   sudo env JKB_DATA=… JKB_FC_RELEASE=… JKB_BASELAYERS=… JKB_AGENT=… \
    ///       <test-bin> --ignored --nocapture monorepo_context_resolves_sibling_path_dep
    #[tokio::test]
    #[ignore = "monorepo context e2e: KVM + root + rust.ext4 + rust runtime layer + agent + build bridge"]
    async fn monorepo_context_resolves_sibling_path_dep() {
        let data = match std::env::var("JKB_DATA") {
            Ok(d) => PathBuf::from(d),
            Err(_) => {
                eprintln!("skip: set JKB_DATA");
                return;
            }
        };
        let src = data.join("monorepo-fixture-src");
        write_rust_monorepo(&src, /* with_context */ true);
        // Keep project_id SHORT: it feeds the jailer chroot + Firecracker UNIX socket
        // path, which must stay under SUN_LEN (108 bytes).
        let Some(fx) = networked_lang_build(
            "mono",
            "onbox-mono.redb",
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
            1,
        )
        .await
        else {
            return;
        };
        let Some((store_dir, agent_bin)) = resolve_runtime_env(&fx) else {
            return;
        };
        let body = boot_layered_and_curl(
            &fx,
            &store_dir,
            &agent_bin,
            "monop",
            "172.25.0.1",
            "172.25.0.2",
            "AA:FC:00:00:25:02",
        )
        .await
        .expect("agent should serve HTTP 200 from the monorepo server (sibling path-dep linked)");
        assert_eq!(
            body, "ok",
            "the served body is the SIBLING crate's `common::body()`"
        );
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: monorepo `context = \".\"` -> ../common resolves -> layered rust runtime -> HTTP 200 ({body:?})"
        );
    }

    /// Negative control proving the feature is load-bearing: the SAME workspace fixture
    /// WITHOUT `context` mounts only `server/`, so `../common` is absent and the build
    /// MUST fail (cargo can't load the path-dep). If this ever passes, the positive test
    /// above proves nothing.
    #[tokio::test]
    #[ignore = "monorepo context e2e (negative): KVM + root + rust.ext4 + build bridge"]
    async fn monorepo_without_context_fails() {
        let data = match std::env::var("JKB_DATA") {
            Ok(d) => PathBuf::from(d),
            Err(_) => {
                eprintln!("skip: set JKB_DATA");
                return;
            }
        };
        let src = data.join("monorepo-fixture-src-nocontext");
        write_rust_monorepo(&src, /* with_context */ false);
        let Some(res) = networked_lang_build_try(
            "moneg",
            "onbox-moneg.redb",
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
            1,
        )
        .await
        else {
            return;
        };
        let err = match res {
            Ok(_) => panic!(
                "build WITHOUT `context` unexpectedly SUCCEEDED — only server/ is mounted, so the \
                 `../common` sibling path-dep should be absent and cargo should fail"
            ),
            Err(e) => format!("{e:#}"),
        };
        // Must fail INSIDE the build (the buildpack/cargo can't load the path-dep), not
        // earlier on some unrelated host-side precheck (e.g. the SUN_LEN socket-path
        // guard) — otherwise this control proves nothing about the `context` feature.
        let lc = err.to_lowercase();
        assert!(
            err.contains("api:") && !lc.contains("socket") && !lc.contains("sun_len"),
            "expected an in-VM build failure for the missing `../common` sibling, got: {err}"
        );
        println!(
            "PASS (negative): no `context` -> ../common absent -> build fails as expected\n  error: {err}"
        );
    }

    /// On-box validation of the VM re-adoption kernel-touching primitives (zero-bounce continuity
    /// phase 1, docs/vm-readoption-design.md): the `jkbase-runtime` cgroup ESCAPE, the SO_PEERCRED
    /// binding, `adopt_writer` re-fencing a LIVE loop at a fresh epoch WITHOUT detaching/disturbing
    /// the running guest, `adopt()` taking over a survivor, and the no-op adopted `Drop`. Boots a
    /// real bun server VM with a data disk, simulates the old server releasing its lease, then
    /// re-fences + re-adopts the still-serving FC.
    ///
    /// NOT covered here (need a systemd-managed jkbase-server → staging/prod gate): the actual
    /// KillMode=mixed survival across `systemctl restart`, and the full deploy→handoff→restart→
    /// adopt server flow. The adopted `stop()`/`hibernate()` by-pid+/proc logic is unit-tested
    /// (an Owned handle reaps the child cleanly here to avoid a test-only zombie; in prod the
    /// survivor reparents to init).
    ///
    /// Run: `tools/dev test vm_readoption_primitives_on_box`
    #[tokio::test]
    #[ignore = "needs KVM + root + bun.ext4 + agent rootfs; proves the re-adoption kernel primitives"]
    async fn vm_readoption_primitives_on_box() {
        use jkbase_orch::vm::{VmConfig, VmInstance};
        use jkbase_substrate::{DataDiskProvider, FlockLease, Lease, LocalLoop};

        let Some(fx) = bun_pipeline_build("readopt", 77, Workload::OfflineNoDep).await else {
            return;
        };
        let Some((store_dir, _agent)) = resolve_runtime_env(&fx) else {
            return;
        };

        // Plain-server metadata image (no in-guest data mount — we only need the FC to OPEN the
        // data loop so adopt_writer's /proc/<pid>/fd proof has something to find).
        let plan = crate::layer_plan::compute_layer_plan(&fx.staged, &store_dir, false, true)
            .expect("layer plan");
        let meta_img = fx.data.join("readopt-metadata.ext4");
        crate::layer_plan::build_metadata_image(
            &fx.staged,
            &plan,
            &Default::default(),
            &Default::default(),
            None,
            None,
            &meta_img,
        )
        .expect("metadata image");

        let cas_dir = fx.data.join("base-rootfs");
        let staging_rootfs = std::env::var("JKB_ROOTFS")
            .map(PathBuf::from)
            .unwrap_or_else(|_| fx.data.join("base-rootfs.ext4"));
        let (rootfs_path, _hash) =
            crate::rootfs_cas::place(&staging_rootfs, &cas_dir).expect("CAS place rootfs");

        // A real data disk on a real loop, attached at epoch 1 (the "old server" fence).
        let id = "readopt";
        let disks = LocalLoop::open(fx.data.join("readopt-disks")).expect("open localloop");
        disks
            .ensure(id, 64 * 1024 * 1024)
            .await
            .expect("ensure data disk");
        let lease =
            FlockLease::open(fx.data.join("readopt-leases"), "old-server").expect("open lease");
        let token1 = lease
            .acquire(id, "old-server", Duration::from_secs(30))
            .await
            .expect("acquire epoch 1");
        let dev = disks.attach_rwo(id, &token1).await.expect("attach_rwo");
        let loop_dev = dev.path.to_string_lossy().into_owned();

        // Point-to-point tap on its own /24 (clear of the other on-box tests).
        let (host_ip, guest_ip, guest_mac) = ("172.29.0.1", "172.29.0.2", "AA:FC:00:00:29:02");
        let tap = "jkreadopt";
        let _ = sh("ip", &["link", "del", tap]).await;
        sh("ip", &["tuntap", "add", "dev", tap, "mode", "tap"])
            .await
            .unwrap();
        sh("ip", &["addr", "add", &format!("{host_ip}/24"), "dev", tap])
            .await
            .unwrap();
        sh("ip", &["link", "set", tap, "up"]).await.unwrap();

        let parent = PathBuf::from(crate::RUNTIME_CGROUP_PARENT);
        let cfg = VmConfig {
            firecracker_bin: fx.fc_release.join("firecracker-v1.15.1-x86_64"),
            kernel_path: fx.kernel.clone(),
            rootfs_path,
            metadata_image_path: Some(meta_img),
            layer_paths: plan.layer_paths.clone(),
            data_disk_path: Some(dev.path.clone()),
            vcpu_count: 2,
            mem_size_mib: 1024,
            tap_device: Some(tap.to_string()),
            guest_mac: Some(guest_mac.to_string()),
            guest_ip: Some(guest_ip.to_string()),
            gateway_ip: Some(host_ip.to_string()),
            vsock_cid: None,
            runtime_cgroup_parent: Some(parent.clone()),
        };
        let runtime_dir = fx.data.join("readopt-run");
        let mut vm = VmInstance::start(id, &cfg, &runtime_dir)
            .await
            .expect("boot runtime VM");
        assert!(
            poll_http_200(guest_ip, 80, Duration::from_secs(75))
                .await
                .is_some(),
            "the booted VM must serve HTTP 200"
        );
        let fc_pid = vm.pid().expect("fc pid");
        let starttime = crate::proc_starttime(fc_pid).expect("fc starttime");

        // (1) cgroup ESCAPE: the FC was migrated into jkbase-runtime/<id> (a sibling of
        //     jkbase.service), the precondition for surviving KillMode=mixed.
        let procs =
            std::fs::read_to_string(parent.join(id).join("cgroup.procs")).unwrap_or_default();
        assert!(
            procs.lines().any(|l| l.trim() == fc_pid.to_string()),
            "FC pid {fc_pid} must be in {}/{id}/cgroup.procs (cgroup escape) — got {procs:?}",
            parent.display()
        );
        eprintln!("[readopt] cgroup escape OK: pid {fc_pid} in jkbase-runtime/{id}");

        // (2) SO_PEERCRED binds the api-sock probe to fc_pid.
        let sock = runtime_dir.join(id).join("firecracker.sock");
        assert_eq!(
            crate::socket_peer_pid(&sock),
            Some(fc_pid),
            "api-sock SO_PEERCRED peer must equal fc_pid"
        );
        eprintln!("[readopt] SO_PEERCRED OK: peer == {fc_pid}");

        // --- Simulate the OLD server exiting: its flock releases; the FC keeps running. ---
        lease.release(&token1).await.expect("release epoch 1");

        // --- The NEW server re-fences at a fresh (higher) epoch WITHOUT detaching the live loop. ---
        let token2 = lease
            .acquire(id, "new-server", Duration::from_secs(30))
            .await
            .expect("acquire epoch 2");
        assert!(token2.epoch > token1.epoch, "re-fence epoch must be higher");
        disks
            .adopt_writer(id, &token2, &loop_dev, fc_pid, starttime)
            .await
            .expect("adopt_writer must re-pin the live writer without detaching");
        assert!(
            poll_http_200(guest_ip, 80, Duration::from_secs(15))
                .await
                .is_some(),
            "the guest must keep serving 200 across adopt_writer (no detach / no disturbance)"
        );
        eprintln!(
            "[readopt] adopt_writer OK: re-pinned at epoch {} — guest still serving 200",
            token2.epoch
        );

        // (3) adopt() takes over the survivor; the agent answers through the adopted handle; and
        //     dropping the adopted handle must NOT kill it (no-op adopted Drop).
        let adopted = VmInstance::adopt(id, &runtime_dir, fc_pid, starttime, Some(&parent));
        assert_eq!(adopted.pid(), Some(fc_pid), "adopted pid() must be fc_pid");
        assert!(
            crate::agent_alive(guest_ip).await,
            "the agent must answer through the adopted survivor"
        );
        drop(adopted);
        assert!(
            crate::proc_alive_at(fc_pid, starttime),
            "dropping the adopted handle must NOT kill the survivor (no-op Drop)"
        );
        assert!(
            poll_http_200(guest_ip, 80, Duration::from_secs(10))
                .await
                .is_some(),
            "survivor must still serve 200 after the adopted handle is dropped"
        );
        eprintln!("[readopt] adopt() OK + adopted Drop is a no-op (survivor still serving)");

        // Clean teardown via the Owned handle: reaps the child cleanly (no zombie) + rmdir's the leaf.
        vm.stop().await.expect("stop");
        assert!(
            !crate::proc_alive_at(fc_pid, starttime),
            "stop() must kill the FC"
        );
        assert!(
            !parent.join(id).exists(),
            "stop() must rmdir the now-empty cgroup leaf"
        );
        let _ = disks.destroy(id).await;
        let _ = lease.release(&token2).await;
        let _ = sh("ip", &["link", "del", tap]).await;
        let _ = std::fs::remove_dir_all(&fx.staged);
        println!(
            "PASS: VM re-adoption primitives — cgroup escape + SO_PEERCRED + adopt_writer (live, \
             no disturbance) + adopt + no-op adopted Drop + leaf rmdir"
        );
    }
}
