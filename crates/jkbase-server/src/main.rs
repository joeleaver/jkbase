mod build_orchestrator;
mod egress;
mod layer_plan;
mod log_shipper;
mod metering;

use anyhow::{Context, Result};
use clap::Parser;
use jkbase_control::api::{self, AppState};
use jkbase_control::logstore::LogStore;
use jkbase_control::store::{
    month_start_epoch, DomainKind, DomainRecord, DomainStatus, ProjectState, QuotaStatus,
    SnapshotMeta, Store, VmAllocation,
};
use log_shipper::LogShipper;
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_substrate::{DataDiskProvider, FenceToken, FlockLease, Lease, LocalLoop, SubstrateError};
use jkbase_proxy::tls::CertManager;
use jkbase_proxy::{
    self, new_domain_map, new_routing_table, ActivityTracker, DomainMap, DomainTarget, ProxyConfig,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use tracing::{info, warn};

#[derive(Parser)]
#[command(name = "jkbase-server", about = "jkbase platform server")]
struct Args {
    #[arg(long, default_value = "/var/jkbase")]
    data_dir: PathBuf,

    #[arg(long)]
    fc_dir: PathBuf,

    #[arg(long)]
    agent_bin: PathBuf,

    #[arg(long, default_value = "9090")]
    api_port: u16,

    #[arg(long, default_value = "8080")]
    proxy_port: u16,

    #[arg(long, default_value = "jkbase.app")]
    domain: String,

    #[arg(long)]
    tls: bool,

    #[arg(long, default_value = "443")]
    https_port: u16,

    #[arg(long, env = "CLOUDFLARE_API_TOKEN")]
    cloudflare_token: Option<String>,

    #[arg(long, env = "CLOUDFLARE_ZONE_ID")]
    cloudflare_zone_id: Option<String>,

    #[arg(long, env = "ACME_EMAIL")]
    acme_email: Option<String>,

    /// Idle timeout in seconds before VMs hibernate (0 = disable)
    #[arg(long, default_value = "300")]
    idle_timeout_secs: u64,

    /// Use the Let's Encrypt staging environment (untrusted certs; avoids prod rate limits)
    #[arg(long)]
    acme_staging: bool,

    /// Bind address for the build egress proxy (host-side default-deny forward
    /// proxy with allowlist + public-IP pinning). Disabled when unset. Build VMs
    /// route their dependency fetches through this; bind it where only the build
    /// network can reach it (e.g. the build gateway IP). Ignored when --build-net
    /// is set (then it binds on the build gateway automatically).
    #[arg(long)]
    egress_addr: Option<String>,

    /// Enable the isolated build network so build VMs fetch deps through the
    /// egress proxy and are sealed for compile (provision the bridge + firewall
    /// first with tools/setup-build-net.sh).
    #[arg(long)]
    build_net: bool,

    #[arg(long, default_value = "jkbuild0")]
    build_bridge: String,

    #[arg(long, default_value = "172.31.0.1")]
    build_gateway: String,

    #[arg(long, default_value = "3128")]
    build_proxy_port: u16,

    /// Platform-operator admin token. When set, a `POST /projects/{id}/quota`
    /// bearing `X-Admin-Token: <this>` may raise per-project limits ABOVE the
    /// platform defaults and target any project. Unset (default) = no admin path:
    /// every tenant stays clamped to defaults. This is an OPERATOR credential,
    /// not a tenant privilege — keep it out of tenant reach.
    #[arg(long, env = "JKBASE_ADMIN_TOKEN")]
    admin_token: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum VmLifecycle {
    Running,
    Hibernated,
    Waking,
    Hibernating,
}

struct PlatformState {
    vms: HashMap<String, VmInstance>,
    vm_states: HashMap<String, VmLifecycle>,
    store: Store,
    firecracker_bin: PathBuf,
    kernel_path: PathBuf,
    base_rootfs_path: PathBuf,
    data_dir: PathBuf,
    /// Read-write-once data-disk provider (R3) + exclusive lease (R2) — every data
    /// disk is fenced through these so a restored/relocated VM can never write a disk
    /// a prior VM still holds. Single-node today (LocalLoop + FlockLease); the same
    /// seam swaps to CephRbd + EtcdLease for HA.
    data_disk: Arc<dyn DataDiskProvider>,
    lease: Arc<dyn Lease>,
    /// The live fence token per project that currently holds its data disk RWO.
    disk_tokens: HashMap<String, FenceToken>,
    /// This host's stable identity, stamped into lease tokens.
    host_id: String,
}

/// Data disk size (MiB) created on first use for projects that declare volumes.
const DATA_DISK_MIB: u64 = 1024;
/// Data-disk lease TTL. Renewed implicitly by holding the VM; released on teardown.
const DISK_LEASE_TTL: Duration = Duration::from_secs(3600);

impl PlatformState {
    fn allocate_ip(&self) -> Result<(String, String, String)> {
        let existing = self.store.list_vm_allocations()?;
        let used_octets: HashSet<u8> = existing
            .iter()
            .filter_map(|a| a.ip.split('.').next_back()?.parse::<u8>().ok())
            .collect();

        for octet in 2..=254u8 {
            if !used_octets.contains(&octet) {
                let ip = format!("172.16.0.{octet}");
                let tap = format!("tap{}", octet - 2);
                let mac = format!("AA:FC:00:00:00:{octet:02X}");
                return Ok((ip, tap, mac));
            }
        }

        anyhow::bail!("no available IP addresses in 172.16.0.0/24");
    }
}

/// Pick the guest kernel: prefer the bumped 6.12 LTS image (erofs/fs-verity/
/// dm-verity — required for the layered runtime) when present, else fall back to
/// the historical `vmlinux.bin` so a server whose provisioning hasn't published
/// 6.12 yet still boots. Used for both the runtime VM and the build-kernel source.
fn resolve_guest_kernel(fc_dir: &std::path::Path) -> std::path::PathBuf {
    let lts = fc_dir.join("vmlinux-6.12.92.bin");
    if lts.exists() {
        lts
    } else {
        fc_dir.join("vmlinux.bin")
    }
}

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let data_dir = args.data_dir.clone();
    let guest_kernel = resolve_guest_kernel(&args.fc_dir);
    tracing::info!(kernel = %guest_kernel.display(), "guest kernel selected");

    tokio::fs::create_dir_all(&data_dir).await?;

    let db_path = data_dir.join("jkbase.redb");
    let deploy_dir = data_dir.join("hosting");
    tokio::fs::create_dir_all(&deploy_dir).await?;

    let store = Store::open(&db_path)?;
    let logs_dir = data_dir.join("logs");
    tokio::fs::create_dir_all(&logs_dir).await?;
    let log_store = LogStore::new(logs_dir.clone());
    let log_shipper = LogShipper::new(log_store.clone(), logs_dir.join(".cursors.json"));
    let routing_table = new_routing_table();
    let domain_map: DomainMap = new_domain_map();
    let activity_tracker: ActivityTracker = Arc::new(RwLock::new(HashMap::new()));

    let base_rootfs_path = data_dir.join("base-rootfs.ext4");
    rootfs::build_base_rootfs(&args.agent_bin, &base_rootfs_path).await?;

    // Data-disk RWO substrate: R3 LocalLoop (loop-device exclusivity) + R2 FlockLease
    // (monotonic fence token). Migrate any legacy `{id}.ext4` disks to LocalLoop's
    // `{id}.img` naming so they become loop-managed + fenced.
    let host_id = std::fs::read_to_string("/proc/sys/kernel/hostname")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "node-local".to_string());
    let data_disks_dir = data_dir.join("data-disks");
    migrate_legacy_data_disks(&data_disks_dir).await?;
    let data_disk: Arc<dyn DataDiskProvider> = Arc::new(LocalLoop::open(&data_disks_dir)?);
    let lease: Arc<dyn Lease> =
        Arc::new(FlockLease::open(data_dir.join("leases"), host_id.clone())?);

    let platform = Arc::new(Mutex::new(PlatformState {
        vms: HashMap::new(),
        vm_states: HashMap::new(),
        store: store.clone(),
        firecracker_bin: args
            .fc_dir
            .join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: guest_kernel.clone(),
        base_rootfs_path,
        data_dir: data_dir.clone(),
        data_disk,
        lease,
        disk_tokens: HashMap::new(),
        host_id,
    }));

    // Build the TLS cert manager up front (wildcard via DNS-01 + on-demand
    // per-custom-domain certs via HTTP-01) so we can wire issuance into AppState.
    let cert_manager: Option<Arc<CertManager>> = if args.tls {
        let cf_token = args
            .cloudflare_token
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--cloudflare-token required when --tls is enabled"))?;
        let cf_zone = args
            .cloudflare_zone_id
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--cloudflare-zone-id required when --tls is enabled"))?;
        let acme_email = args
            .acme_email
            .clone()
            .ok_or_else(|| anyhow::anyhow!("--acme-email required when --tls is enabled"))?;
        let tls_config = jkbase_proxy::tls::TlsConfig {
            domain: args.domain.clone(),
            cert_dir: data_dir.join("certs"),
            cloudflare_token: cf_token,
            cloudflare_zone_id: cf_zone,
            acme_email,
        };
        Some(CertManager::new(tls_config, domain_map.clone(), args.acme_staging).await?)
    } else {
        None
    };

    let store_for_builds = store.clone();
    let mut state = AppState::new(store, log_store.clone(), deploy_dir);
    state.routing_table = Some(routing_table.clone());
    state.domain_map = Some(domain_map.clone());
    state.platform_domain = args.domain.clone();
    state.admin_token = args.admin_token.clone();
    if let Some(ref cm) = cert_manager {
        let cm_req = cm.clone();
        state.cert_request = Some(Arc::new(move |host: String| {
            let cm = cm_req.clone();
            tokio::spawn(async move { cm.ensure_cert(&host).await });
        }));
        let cm_status = cm.clone();
        state.cert_status = Some(Arc::new(move |host: &str| cm_status.has_cert(host)));
    }

    let platform_for_cb = platform.clone();
    let routing_for_cb = routing_table.clone();
    let domain_for_cb = domain_map.clone();
    let shipper_for_cb = log_shipper.clone();
    state.deploy_callback = Some(Box::new(move |project_id: String, _version: u64| {
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        let domains = domain_for_cb.clone();
        let shipper = shipper_for_cb.clone();
        Box::pin(async move { handle_deploy(&project_id, platform, routing, domains, shipper).await })
    }));

    let platform_for_teardown = platform.clone();
    state.teardown_callback = Some(Box::new(move |project_id: String| {
        let platform = platform_for_teardown.clone();
        Box::pin(async move { handle_teardown(&project_id, &platform).await })
    }));

    // Build-pipeline wiring: control owns the `POST /build` funnel + build-job;
    // this server owns jkbase-orch + the jailer privilege, exposed via
    // `build_callback` (mirrors `deploy_callback`). The kernel is staged onto the
    // data-dir filesystem (same-fs hard-link into the jail), and the parent build
    // cgroup is provisioned best-effort (needs root).
    let fc_release = args.fc_dir.join("release-v1.15.1-x86_64");
    let build_kernel = data_dir.join("build-kernel").join("vmlinux.bin");
    // Non-fatal: a build-provisioning gap disables builds but must not knock over
    // the (separate) runtime hosting path — the kernel here feeds only builds.
    if let Err(e) = build_orchestrator::stage_kernel(&guest_kernel, &build_kernel) {
        tracing::warn!(error = %e, "build kernel staging failed; builds disabled until provisioned");
    }
    // Isolated build network (per-build TAP pool on the build bridge). Build VMs
    // reach only the egress proxy on the gateway; the firewall from
    // tools/setup-build-net.sh enforces it. `None` → offline builds.
    let build_uid = 100_000u32;
    let build_net = if args.build_net {
        Some(Arc::new(build_orchestrator::BuildNet::new(
            args.build_bridge.clone(),
            args.build_gateway.clone(),
            args.build_proxy_port,
            build_uid,
            64, // concurrent build-network slots
        )))
    } else {
        None
    };
    // Fail closed: with --build-net we MUST NOT run attacker-controlled build VMs
    // unless their isolation firewall is actually provisioned + present.
    if let Some(net) = &build_net {
        net.verify_firewall().await?;
    }
    let build_deps = Arc::new(build_orchestrator::BuildDeps {
        jailer_bin: fc_release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: fc_release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: build_kernel,
        data_dir: data_dir.clone(),
        deploy_dir: data_dir.join("hosting"),
        toolchain_dir: data_dir.join("toolchains"),
        store: store_for_builds,
        // Short base: it prefixes the jailer chroot, and the Firecracker API
        // socket path under it must stay within SUN_LEN (~108 bytes).
        chroot_base: data_dir.join("bj"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        parent_cgroup: "jkbase-build".to_string(),
        uid: build_uid,
        gid: build_uid,
        // Sized for real apps (Vite/monorepo builds + sizeable node_modules), not the
        // toy fixtures: a Vite build can use multiple GiB of RAM, the full (dev-incl.)
        // install + source + build output needs GiB of scratch, and the app erofs blob
        // needs room in the output drive even after the production prune. The cgroup
        // memory cap (> guest RAM) keeps a hostile build from host-OOM. Tunable per box.
        timeout: Duration::from_secs(900),
        vcpu_count: 4,
        mem_size_mib: 4096,
        cgroup_pids_max: 1024,
        cgroup_mem_max_bytes: 4608 * 1024 * 1024,
        cgroup_cpu_max: "400000 100000".to_string(),
        scratch_size_bytes: 4096 * 1024 * 1024,
        output_size_bytes: 1024 * 1024 * 1024,
        console_log_max_bytes: 1024 * 1024,
        max_concurrent: 4,
        net: build_net,
        fetch_deadline: Duration::from_secs(600),
    });
    // The jail chroot base + toolchain dir must exist on the data-dir fs.
    let _ = std::fs::create_dir_all(&build_deps.chroot_base);
    let _ = std::fs::create_dir_all(&build_deps.toolchain_dir);
    build_orchestrator::provision_cgroup(&build_deps.cgroup_mount, &build_deps.parent_cgroup);
    // Fail builds left mid-flight by a previous crash + reap their orphan dirs.
    build_orchestrator::reconcile_on_boot(&build_deps.store, &build_deps.data_dir, &build_deps.deploy_dir);
    state.build_callback = Some(build_orchestrator::build_callback(build_deps));

    let state = Arc::new(state);
    let router = api::router(state, args.domain.clone());

    // Set up wake callback for the proxy
    let platform_for_wake = platform.clone();
    let routing_for_wake = routing_table.clone();
    let domain_for_wake = domain_map.clone();
    let shipper_for_wake = log_shipper.clone();
    let wake_callback: jkbase_proxy::WakeCallback =
        Arc::new(move |project_id: String| {
            let platform = platform_for_wake.clone();
            let routing = routing_for_wake.clone();
            let domains = domain_for_wake.clone();
            let shipper = shipper_for_wake.clone();
            Box::pin(async move { wake_project(&project_id, platform, routing, domains, shipper).await })
        });

    let api_addr = format!("127.0.0.1:{}", args.api_port);
    let proxy_config = ProxyConfig {
        http_port: args.proxy_port,
        https_port: if args.tls { Some(args.https_port) } else { None },
        platform_domain: args.domain,
        cert_manager: cert_manager.clone(),
        api_addr: Some(api_addr),
        domains: Some(domain_map.clone()),
        activity_tracker: Some(activity_tracker.clone()),
        wake_callback: Some(wake_callback),
    };
    let proxy_port = proxy_config.http_port;
    let proxy_routes = routing_table.clone();

    // Reconcile state and build the domain map BEFORE the proxy serves traffic,
    // or apex/www/console would 404 in the gap.
    reap_orphan_firecrackers_on_boot().await;
    cleanup_orphans(&platform).await;
    reconcile_orphans_on_boot(&platform).await;
    backfill_domains(&platform, &domain_map).await;

    tokio::spawn(async move {
        if let Err(e) = jkbase_proxy::serve(proxy_config, proxy_routes).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    // Spawn log shipper loop (pulls guest logs into the persistent store)
    tokio::spawn(log_shipper_loop(platform.clone(), log_shipper.clone()));

    // Spawn idle detection loop
    if args.idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(args.idle_timeout_secs);
        info!(timeout_secs = args.idle_timeout_secs, "idle detection enabled");
        tokio::spawn(idle_detection_loop(
            platform.clone(),
            routing_table.clone(),
            activity_tracker.clone(),
            idle_timeout,
            log_shipper.clone(),
        ));
    }

    // Spawn the scheduled-functions loop (host-driven cron). Reads the durable
    // SCHEDULES registry each tick, wakes + invokes due functions.
    tokio::spawn(scheduler_loop(
        platform.clone(),
        routing_table.clone(),
        domain_map.clone(),
        log_shipper.clone(),
        activity_tracker.clone(),
    ));

    // Spawn the metering + quota-enforcement loop. Samples per-project CPU,
    // bandwidth, and storage into hourly rollup buckets and hibernates +
    // blocks projects that exceed their monthly bandwidth cap.
    tokio::spawn(metering_loop(
        platform.clone(),
        routing_table.clone(),
        log_shipper.clone(),
    ));

    // Spawn the build egress proxy (default-deny forward proxy + SSRF defense).
    // With --build-net it binds on the build gateway (where the firewall lets the
    // build VMs reach it); otherwise on an explicit --egress-addr.
    let egress_addr = if args.build_net {
        Some(format!("{}:{}", args.build_gateway, args.build_proxy_port))
    } else {
        args.egress_addr.clone()
    };
    if let Some(egress_addr) = egress_addr {
        let cfg = Arc::new(egress::EgressConfig::with_default_allowlist());
        tokio::spawn(async move {
            match tokio::net::TcpListener::bind(&egress_addr).await {
                Ok(listener) => {
                    info!(addr = %egress_addr, "egress proxy starting");
                    egress::serve(listener, cfg).await;
                }
                Err(e) => {
                    tracing::error!(error = %e, addr = %egress_addr, "failed to bind egress proxy")
                }
            }
        });
    }

    let addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        api = %addr,
        proxy = %format!("0.0.0.0:{proxy_port}"),
        "jkbase-server listening"
    );

    let platform_for_shutdown = platform.clone();
    let routing_for_shutdown = routing_table.clone();
    let shipper_for_shutdown = log_shipper.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(
            platform_for_shutdown,
            routing_for_shutdown,
            shipper_for_shutdown,
        ))
        .await?;

    Ok(())
}

async fn shutdown_signal(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
) {
    let ctrl_c = tokio::signal::ctrl_c();
    let mut sigterm = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("failed to register SIGTERM handler");

    tokio::select! {
        _ = ctrl_c => {},
        _ = sigterm.recv() => {},
    }
    info!("shutdown signal received, hibernating running VMs...");

    let running_projects: Vec<String> = {
        let plat = platform.lock().await;
        plat.vm_states
            .iter()
            .filter(|(_, state)| **state == VmLifecycle::Running)
            .map(|(id, _)| id.clone())
            .collect()
    };

    for project_id in &running_projects {
        info!(project = %project_id, "hibernating for shutdown");
        if let Err(e) =
            hibernate_project(project_id, platform.clone(), routing.clone(), shipper.clone()).await
        {
            // hibernate_project self-cleans its own wedge/timeout paths; this is a
            // last-resort catch for an unexpected Err, routed through the same helper.
            tracing::error!(project = %project_id, error = %e, "hibernate errored, force stopping");
            force_stop_and_cleanup(project_id, &platform).await;
        }
    }

    info!("all VMs hibernated, shutdown complete");
}

async fn cleanup_orphans(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let allocs = match plat.store.list_vm_allocations() {
        Ok(a) => a,
        Err(_) => return,
    };

    for alloc in &allocs {
        let reachable = tokio::time::timeout(
            Duration::from_secs(2),
            tokio::net::TcpStream::connect(format!("{}:80", alloc.ip)),
        )
        .await
        .map(|r| r.is_ok())
        .unwrap_or(false);

        if !reachable {
            info!(
                project = %alloc.project_id,
                ip = %alloc.ip,
                "cleaning up orphaned allocation"
            );
            let _ = teardown_tap(&alloc.tap_device).await;
            let _ = plat.store.remove_vm_allocation(&alloc.project_id);
        }
    }
}

/// Fully reap a deleted project (the `teardown_callback` control invokes from
/// `DELETE /projects/{id}`): stop the VM, free its IP/TAP allocation, drop its
/// snapshot, and remove every on-disk artifact. Best-effort + idempotent — any
/// step that fails is reconciled by `reconcile_orphans_on_boot` on the next boot.
async fn handle_teardown(project_id: &str, platform: &Arc<Mutex<PlatformState>>) -> Result<()> {
    // Reap under the platform lock, but only once no wake/hibernate is mid-flight for
    // this project: those drop the lock during the slow VM op, and destroying the disk
    // under a live restoring VM would free a loop device another project could reuse
    // (silent corruption). Wait it out (bounded ~30s), then do stop + release + destroy
    // in ONE locked section so a new wake can't interleave (it needs the lock to set
    // Waking).
    let (alloc, data_dir) = {
        let mut attempt = 0;
        loop {
            let mut plat = platform.lock().await;
            if attempt < 150
                && matches!(
                    plat.vm_states.get(project_id),
                    Some(VmLifecycle::Waking) | Some(VmLifecycle::Hibernating)
                )
            {
                drop(plat);
                attempt += 1;
                tokio::time::sleep(Duration::from_millis(200)).await;
                continue;
            }
            if let Some(mut vm) = plat.vms.remove(project_id) {
                let _ = vm.stop().await;
            }
            // Force-kill ANY Firecracker for this project — including one a wake that
            // outlasted our wait-loop hasn't yet recorded in `vms` — BEFORE we destroy
            // the disk, so `destroy()` can never detach a loop device a live VM still
            // maps (which another project could then be handed = corruption). The wake,
            // finding its FC dead, fails and its guard releases.
            reap_firecracker(project_id).await;
            // Release the data-disk lease + destroy the disk (detach loop device,
            // remove the image + holder record) as part of reaping the project.
            if let Some(token) = plat.disk_tokens.remove(project_id) {
                let ls = plat.lease.clone();
                let _ = ls.release(&token).await;
            }
            let dd = plat.data_disk.clone();
            let _ = dd.destroy(project_id).await;
            plat.vm_states.remove(project_id);
            let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();
            let _ = plat.store.remove_snapshot_meta(project_id);
            let _ = plat.store.remove_vm_allocation(project_id);
            break (alloc, plat.data_dir.clone());
        }
    };

    // Kill any leaked Firecracker that outlived the handle, then drop its TAP.
    let _ = tokio::process::Command::new("pkill")
        .args(["-f", &format!("firecracker.*{project_id}")])
        .status()
        .await;
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
    remove_project_artifacts(&data_dir, project_id).await;
    info!(project = %project_id, "project torn down");
    Ok(())
}

/// Remove every per-project on-disk artifact (content image, data disk, snapshot,
/// run dir, hosting tree, build workspace). Best-effort; absent paths are ignored.
async fn remove_project_artifacts(data_dir: &Path, project_id: &str) {
    let _ =
        tokio::fs::remove_file(data_dir.join("content-images").join(format!("{project_id}.ext4")))
            .await;
    // Data disk: legacy `.ext4` plus the loop-managed `.img` + its holder record.
    let disks = data_dir.join("data-disks");
    for f in [format!("{project_id}.ext4"), format!("{project_id}.img"), format!("{project_id}.holder")] {
        let _ = tokio::fs::remove_file(disks.join(f)).await;
    }
    for dir in ["snapshots", "run", "hosting", "builds"] {
        let _ = tokio::fs::remove_dir_all(data_dir.join(dir).join(project_id)).await;
    }
    // Per-project git bare repo (build·D push-to-deploy): `git/{id}.git`.
    let _ =
        tokio::fs::remove_dir_all(data_dir.join("git").join(format!("{project_id}.git"))).await;
}

/// Reap every runtime Firecracker left over from a previous (crashed/restarted) server
/// BEFORE we wake any project. On a fresh start `vms` is empty, so any running runtime
/// microVM is an orphan we no longer own — and a surviving writer, combined with a wake
/// that preempts a now-stale holder record, would put two writers on one data disk.
/// The server re-boots/re-restores the projects it should run. (Build VMs run jailed
/// and none are in flight at boot.)
async fn reap_orphan_firecrackers_on_boot() {
    let _ = tokio::process::Command::new("pkill")
        .args(["-9", "-f", "firecracker-v1.15.1-x86_64"])
        .status()
        .await;
}

/// Boot-time sweep for projects deleted but left with artifacts behind (a teardown
/// that failed midway, or a project removed before teardown existed). For every
/// per-project image/dir whose name is NOT a currently registered project, drop the
/// stale artifact. Registered projects are never touched, so live data disks are
/// safe. `builds/` is reaped wholesale by the build reconcile, so it is omitted.
async fn reconcile_orphans_on_boot(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let registered: HashSet<String> = match plat.store.list_projects() {
        Ok(ps) => ps.into_iter().map(|p| p.id).collect(),
        Err(_) => return,
    };
    let data_dir = plat.data_dir.clone();
    drop(plat);

    // Collect each directory's entries up front: removing files while iterating a
    // live read_dir handle skips entries (the kernel readdir cursor shifts under
    // the deletions), so a single pass would reap only a subset of the orphans.
    // content-images: `{id}.ext4`.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("content-images")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".ext4") else { continue };
            if !registered.contains(id) {
                let _ = std::fs::remove_file(entry.path());
                info!(project = %id, artifact = "content-images", "reaped orphaned artifact");
            }
        }
    }
    // data-disks: loop-managed `{id}.img` + its `{id}.holder` record (+ legacy
    // `{id}.ext4`). Detach any loop device still bound to an orphan image before
    // removing it, so deleted projects can't leak loop devices that another project
    // would later reuse.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("data-disks")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name
                .strip_suffix(".img")
                .or_else(|| name.strip_suffix(".holder"))
                .or_else(|| name.strip_suffix(".ext4"))
            else {
                continue;
            };
            if registered.contains(id) {
                continue;
            }
            let path = entry.path();
            if name.ends_with(".img")
                && let Ok(out) = tokio::process::Command::new("losetup")
                    .args(["-j", &path.to_string_lossy()])
                    .output()
                    .await
            {
                for dev in String::from_utf8_lossy(&out.stdout)
                    .lines()
                    .filter_map(|l| l.split(':').next())
                    .filter(|d| !d.is_empty())
                {
                    let _ = tokio::process::Command::new("losetup")
                        .args(["-d", dev])
                        .status()
                        .await;
                }
            }
            let _ = std::fs::remove_file(&path);
            info!(project = %id, artifact = "data-disks", "reaped orphaned artifact");
        }
    }
    for sub in ["hosting", "run", "snapshots"] {
        let Ok(entries) = std::fs::read_dir(data_dir.join(sub)) else {
            continue;
        };
        let entries: Vec<_> = entries.flatten().collect();
        for entry in entries {
            if !entry.file_type().map(|t| t.is_dir()).unwrap_or(false) {
                continue;
            }
            let id = entry.file_name().to_string_lossy().to_string();
            if !registered.contains(&id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = %sub, "reaped orphaned dir");
            }
        }
    }
    // git bare repos (build·D push-to-deploy): `git/{id}.git` dirs. Reaps the
    // bare repo (and its credential's pushed objects) when a delete-time cleanup
    // was missed, so a recreated slug can't inherit them.
    if let Ok(entries) = std::fs::read_dir(data_dir.join("git")) {
        for entry in entries.flatten().collect::<Vec<_>>() {
            let name = entry.file_name().to_string_lossy().to_string();
            let Some(id) = name.strip_suffix(".git") else {
                continue;
            };
            if !registered.contains(id) {
                let _ = std::fs::remove_dir_all(entry.path());
                info!(project = %id, artifact = "git", "reaped orphaned bare repo");
            }
        }
    }
}

/// Reconcile persisted state into the in-memory domain map at startup. Grandfathers
/// each deployed project's primary subdomain and any legacy `project.domains` into
/// the DOMAINS registry as Active (trusted prod data — no re-verification), then
/// loads all Active domains into the map so hosts resolve before traffic arrives.
async fn backfill_domains(platform: &Arc<Mutex<PlatformState>>, domain_map: &DomainMap) {
    let active = {
        let mut plat = platform.lock().await;
        let projects = match plat.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to list projects");
                return;
            }
        };

        for project in &projects {
            if project.current_version.is_none() {
                continue;
            }
            match project.state {
                ProjectState::Active | ProjectState::Hibernated => {
                    plat.vm_states
                        .insert(project.id.clone(), VmLifecycle::Hibernated);
                    if project.state == ProjectState::Active {
                        let mut p = project.clone();
                        p.state = ProjectState::Hibernated;
                        let _ = plat.store.update_project(&p);
                    }

                    let tenant_id = project.tenant_id.clone().unwrap_or_default();
                    // Grandfather the primary subdomain (host-key == project id).
                    grandfather_domain(&plat.store, &project.id, &project.id, &tenant_id);
                    // Grandfather legacy project.domains (already-trusted aliases).
                    for host in &project.domains {
                        grandfather_domain(&plat.store, host, &project.id, &tenant_id);
                    }
                }
                ProjectState::Stopped => {}
            }
        }

        plat.store.list_all_domains().unwrap_or_default()
    };

    let mut map = domain_map.write().await;
    let mut count = 0usize;
    for d in active {
        if d.status == DomainStatus::Active {
            map.insert(
                d.host,
                DomainTarget {
                    project_id: d.project_id,
                    site: d.site,
                },
            );
            count += 1;
        }
    }
    info!(domains = count, "domain map built; projects registered for on-demand wake");
}

/// Ensure an Active DomainRecord exists for `host` (idempotent). Used by backfill
/// to migrate pre-registry data without forcing re-verification.
fn grandfather_domain(store: &Store, host: &str, project_id: &str, tenant_id: &str) {
    if matches!(store.get_domain(host), Ok(Some(_))) {
        return;
    }
    let kind = if host.contains('.') {
        DomainKind::Custom
    } else {
        DomainKind::Subdomain
    };
    let record = DomainRecord {
        host: host.to_string(),
        project_id: project_id.to_string(),
        tenant_id: tenant_id.to_string(),
        site: None,
        kind,
        status: DomainStatus::Active,
        token: String::new(),
        created_at: 0,
    };
    let _ = store.claim_domain(&record);
}

async fn handle_deploy(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    let mut plat = platform.lock().await;

    // If hibernated, clear stale snapshot
    if plat.vm_states.get(project_id) == Some(&VmLifecycle::Hibernated) {
        info!(project = %project_id, "clearing snapshot for fresh deploy");
        let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
        let _ = std::fs::remove_dir_all(&snapshot_dir);
        let _ = plat.store.remove_snapshot_meta(project_id);
    }

    if let Some(mut old_vm) = plat.vms.remove(project_id) {
        info!(project = %project_id, "syncing and stopping old VM for redeploy");
        if let Ok(Some(alloc)) = plat.store.get_vm_allocation(project_id) {
            let _ = sync_agent(&alloc.ip).await;
            // Capture any final log lines before the old agent goes away.
            shipper.ship(project_id, &alloc.ip).await;
        }
        let _ = old_vm.stop().await;
    }
    // Release the old VM's data-disk hold (if any) before re-fencing for the new VM —
    // UNCONDITIONALLY: a stop() error or a missing VM handle must not leak the lease
    // (which would then fail the re-fence below with LeaseHeld and brick the redeploy).
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let content_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    if !content_dir.exists() {
        anyhow::bail!("no deployed content for project {project_id}");
    }

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(existing) => {
            info!(project = %project_id, ip = %existing.ip, "reusing persisted IP");
            existing
        }
        None => {
            let (ip, tap, mac) = plat.allocate_ip()?;
            let alloc = VmAllocation {
                project_id: project_id.to_string(),
                ip,
                tap_device: tap,
                mac,
            };
            plat.store.save_vm_allocation(&alloc)?;
            info!(project = %project_id, ip = %alloc.ip, "allocated new IP");
            alloc
        }
    };

    // Read what the slow build + fence + boot need, then DROP the platform lock: the
    // metadata-image build (mkfs + sha256 layer verify), the RWO attach (first-deploy
    // mkfs / reap+300ms / losetup), and the VM boot must NOT head-of-line block every
    // other project on the single platform lock. Re-acquire only to commit.
    let has_disk = check_project_has_volumes(&plat.data_dir, project_id)
        || plat.data_disk.exists(project_id).await.unwrap_or(false);
    let data_dir = plat.data_dir.clone();
    let dd = plat.data_disk.clone();
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();
    let firecracker_bin = plat.firecracker_bin.clone();
    let kernel_path = plat.kernel_path.clone();
    let rootfs_path = plat.base_rootfs_path.clone();
    let runtime_dir = data_dir.join("run");
    // Project secrets → merged into each server's runtime env in the per-project
    // metadata image below (read here under the platform lock). That image is rebuilt
    // ONLY on deploy; wake/restore reuse the last-deployed image (a restored live
    // process can't be re-env'd), so a secret change takes effect on the next DEPLOY,
    // not on an idle wake/restart.
    let secrets: std::collections::BTreeMap<String, String> = plat
        .store
        .list_secrets(project_id)
        .map(|v| v.into_iter().map(|s| (s.key, s.value)).collect())
        .unwrap_or_default();
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Build the per-project metadata image (device map + manifests + static sites)
    // and resolve the erofs layer blobs to attach. Replaces the flat content image:
    // a layered server's root is an overlay of app:runtime:base, so the runtime VM
    // gets the metadata image (vdb) + the layer blobs (vdc..) instead of one blob.
    let content_images_dir = data_dir.join("content-images");
    tokio::fs::create_dir_all(&content_images_dir).await?;
    let metadata_image_path = content_images_dir.join(format!("{project_id}.ext4"));
    let plan = {
        let content_dir = content_dir.clone();
        let store_dir = data_dir.join("baselayers");
        let out = metadata_image_path.clone();
        tokio::task::spawn_blocking(move || -> anyhow::Result<layer_plan::LayerPlan> {
            // verify=true: cold-boot deploy re-checks every tenant + platform blob's
            // sha256 before it can be attached to a VM.
            let plan = layer_plan::compute_layer_plan(&content_dir, &store_dir, has_disk, true)?;
            layer_plan::build_metadata_image(&content_dir, &plan, &secrets, &out)?;
            Ok(plan)
        })
        .await
        .context("metadata image build task")??
    };

    // Fence the data disk read-write-once for projects that declare volumes (or
    // already have a disk): acquire the lease + attach via the RWO provider, preempting
    // any prior writer. Held by an RAII guard until the VM is up, so a boot failure (or
    // a cancelled future) releases the lease instead of bricking the project.
    let disk_guard = if has_disk {
        Some(fence_data_disk(&dd, &ls, &hid, project_id).await?)
    } else {
        None
    };

    let config = VmConfig {
        firecracker_bin,
        kernel_path,
        rootfs_path,
        metadata_image_path: Some(metadata_image_path),
        layer_paths: plan.layer_paths.clone(),
        data_disk_path: disk_guard.as_ref().map(|g| g.device()),
        vcpu_count: 4,
        mem_size_mib: 3072,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };
    // If start fails, `disk_guard` drops here and releases the lease + disk.
    let vm = VmInstance::start(project_id, &config, &runtime_dir).await?;

    // Re-acquire to commit the running VM: record Firecracker's PID as the data-disk
    // writer (so a future attach's liveness check tracks the real writer, not this
    // server), then DISARM the guard and hand the token to disk_tokens.
    let mut plat = platform.lock().await;
    if let Some(guard) = disk_guard {
        if let Some(pid) = vm.pid() {
            let _ = dd.set_writer_pid(project_id, guard.token(), pid).await;
        }
        plat.disk_tokens.insert(project_id.to_string(), guard.disarm());
    }
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    wait_for_agent(&alloc.ip).await?;

    register_active_routes(&routing, &domain_map, &active_domains, project_id, &alloc.ip).await;

    info!(project = %project_id, ip = %alloc.ip, "VM ready, routing active");
    Ok(())
}

/// Point all of a project's Active hosts at its VM IP (fast-path routes) and
/// ensure the shared domain map reflects them. `routes` is keyed by host-key.
async fn register_active_routes(
    routing: &jkbase_proxy::RoutingTable,
    domain_map: &DomainMap,
    active_domains: &[DomainRecord],
    project_id: &str,
    ip: &str,
) {
    let mut table = routing.write().await;
    let mut map = domain_map.write().await;
    // The primary label always routes, even if its DomainRecord predates the registry.
    table.insert(project_id.to_string(), ip.to_string());
    map.entry(project_id.to_string()).or_insert_with(|| DomainTarget {
        project_id: project_id.to_string(),
        site: None,
    });
    for d in active_domains {
        table.insert(d.host.clone(), ip.to_string());
        map.insert(
            d.host.clone(),
            DomainTarget {
                project_id: d.project_id.clone(),
                site: d.site.clone(),
            },
        );
    }
}

async fn hibernate_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    let mut plat = platform.lock().await;

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Running) => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Hibernating);
        }
        _ => anyhow::bail!("project {project_id} is not running"),
    }

    // Remove from the routes fast-path first (new requests will trigger wake).
    // Leave the domain map intact so hibernated hosts still resolve + wake.
    {
        let mut table = routing.write().await;
        table.remove(project_id);
        if let Ok(domains) = plat.store.list_active_domains_for_project(project_id) {
            for d in &domains {
                table.remove(&d.host);
            }
        }
    }

    let mut vm = match plat.vms.remove(project_id) {
        Some(vm) => vm,
        None => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Running);
            anyhow::bail!("no VM instance for {project_id}");
        }
    };

    let snapshot_dir = plat.data_dir.join("snapshots").join(project_id);
    let agent_ip = plat
        .store
        .get_vm_allocation(project_id)
        .ok()
        .flatten()
        .map(|a| a.ip);
    drop(plat);

    // Pre-pause wedge detection: if the agent is unreachable/wedged, skip the
    // flush + pause/snapshot entirely and go straight to a clean force-stop. A
    // wedged guest can't complete a Firecracker Pause+snapshot anyway, and
    // attempting it is what produces the "failed to pause VM" stall.
    let wedged = match &agent_ip {
        Some(ip) => !agent_alive(ip).await,
        None => true, // no allocation/ip -> nothing to pause cleanly
    };
    if wedged {
        tracing::warn!(project = %project_id, "agent unreachable/wedged, force-stopping instead of hibernating");
        force_stop_and_cleanup(project_id, &platform).await;
        return Ok(());
    }

    // Final flush of the agent's buffer before we pause it. Bounded so a wedged
    // agent (that passed the probe but then stalls) can't block shutdown.
    if let Some(ip) = &agent_ip {
        let _ = tokio::time::timeout(Duration::from_secs(3), shipper.ship(project_id, ip)).await;
    }

    // Bound pause+snapshot so one bad VM can't stall the drain of the rest. The
    // budget is generous because snapshotting a 1 GiB mem file is legit slow I/O
    // (Pause itself is sub-second). Any timeout or error -> clean force-stop.
    let (snapshot_path, mem_file_path) =
        match tokio::time::timeout(Duration::from_secs(60), vm.hibernate(&snapshot_dir)).await {
            Ok(Ok(paths)) => paths,
            Ok(Err(e)) => {
                tracing::error!(project = %project_id, error = %e, "hibernate failed, force-stopping");
                drop(vm); // Drop SIGKILLs the process; force_stop handles the rest.
                force_stop_and_cleanup(project_id, &platform).await;
                return Ok(());
            }
            Err(_elapsed) => {
                tracing::error!(project = %project_id, "hibernate timed out (VM wedged), force-stopping");
                drop(vm);
                force_stop_and_cleanup(project_id, &platform).await;
                return Ok(());
            }
        };

    let mut plat = platform.lock().await;

    // The VM is down (hibernate killed the FC); release its data-disk hold NOW —
    // before persisting snapshot meta — so a persistence error can't leak the lease
    // (which would wedge the project in Hibernating + LeaseHeld on the next wake). The
    // image file persists; the next wake re-fences + the restore patches the drive.
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let meta = SnapshotMeta {
        project_id: project_id.to_string(),
        snapshot_path: snapshot_path.to_string_lossy().to_string(),
        mem_file_path: mem_file_path.to_string_lossy().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        vcpu_count: 4,
        mem_size_mib: 3072,
    };
    plat.store.save_snapshot_meta(&meta)?;

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        plat.store.update_project(&proj)?;
    }

    // Keep TAP device and VmAllocation for fast restore
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);

    info!(project = %project_id, "VM hibernated");
    Ok(())
}

/// Wake a project, refusing if it is over an enforced quota. The quota gate
/// reads QUOTA_STATUS (the metering loop's source of truth) so a request racing
/// the over-quota hibernation is still refused. All other failures are transient
/// (`Unavailable`) and the proxy retries them.
async fn wake_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> std::result::Result<String, jkbase_proxy::WakeError> {
    {
        let plat = platform.lock().await;
        if let Ok(Some(status)) = plat.store.get_quota_status(project_id)
            && status.bandwidth_blocked {
                return Err(jkbase_proxy::WakeError::OverQuota(
                    status
                        .blocked_reason
                        .unwrap_or_else(|| "over quota".to_string()),
                ));
            }
    }
    wake_project_inner(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| jkbase_proxy::WakeError::Unavailable(e.to_string()))
}

async fn wake_project_inner(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<String> {
    let mut plat = platform.lock().await;

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Hibernated) => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
        Some(VmLifecycle::Waking) => {
            drop(plat);
            return wait_for_route(project_id, &routing).await;
        }
        Some(VmLifecycle::Running) => {
            let table = routing.read().await;
            if let Some(ip) = table.get(project_id) {
                return Ok(ip.clone());
            }
            anyhow::bail!("VM running but not in routing table");
        }
        Some(VmLifecycle::Hibernating) => {
            // Wait for hibernation to complete, then wake
            drop(plat);
            for _ in 0..100 {
                tokio::time::sleep(Duration::from_millis(100)).await;
                let p = platform.lock().await;
                if p.vm_states.get(project_id) == Some(&VmLifecycle::Hibernated) {
                    drop(p);
                    return Box::pin(wake_project_inner(
                        project_id,
                        platform.clone(),
                        routing,
                        domain_map,
                        shipper,
                    ))
                    .await;
                }
            }
            anyhow::bail!("timed out waiting for {project_id} to finish hibernating");
        }
        None => {
            // No lifecycle state — cold boot
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Waking);
        }
    }

    // Try snapshot restore first, fall back to cold boot
    let snap_meta = plat.store.get_snapshot_meta(project_id)?;

    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(a) => a,
        None => {
            // No allocation — need full cold boot via handle_deploy
            plat.vm_states.remove(project_id);
            drop(plat);
            info!(project = %project_id, "no allocation, cold booting");
            let routing_clone = routing.clone();
            handle_deploy(project_id, platform, routing, domain_map, shipper).await?;
            let table = routing_clone.read().await;
            return table
                .get(project_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("cold boot completed but no route"));
        }
    };

    // The metadata image already exists from deploy (with `_layers.json` baked in);
    // wake reuses it as-is — no rebuild.
    let metadata_image_path = plat
        .data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));

    // Whether this project has a data disk, plus clones of the RWO substrate so the
    // fence (below) can run AFTER dropping the platform lock. data_disk_path is set
    // by the fence; start with None.
    let has_volumes = check_project_has_volumes(&plat.data_dir, project_id);
    let has_disk = has_volumes || plat.data_disk.exists(project_id).await.unwrap_or(false);
    let dd = plat.data_disk.clone();
    let ls = plat.lease.clone();
    let hid = plat.host_id.clone();

    // The erofs layer attach order for the cold-boot fallback (restore re-derives
    // drives from the snapshot, so this only matters when restore fails/misses). Read
    // the sidecar PAIRED with the metadata image — NOT a recompute from `live`, which
    // can drift from the (last successfully built) image's baked `_layers.json` and
    // mis-assign device letters. Absent ⇒ legacy/static image with no layers.
    let layer_paths = layer_plan::read_layer_paths(&metadata_image_path);

    let mut config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path: plat.base_rootfs_path.clone(),
        metadata_image_path: Some(metadata_image_path),
        layer_paths,
        data_disk_path: None,
        vcpu_count: 4,
        mem_size_mib: 3072,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };
    let runtime_dir = plat.data_dir.join("run");
    let active_domains = plat
        .store
        .list_active_domains_for_project(project_id)
        .unwrap_or_default();
    drop(plat);

    setup_tap(&alloc.tap_device).await?;

    // Fence the data disk read-write-once BEFORE restore/boot, so the restored guest
    // — which would otherwise re-derive the RW data drive straight from the snapshot,
    // bypassing the gate — only ever writes through the exclusivity attach. The
    // restore path patches the data drive to this fenced device; refuse→cold-boot
    // (reap + retry, else error) lives in fence_data_disk. None when no data disk.
    let disk_guard = if has_disk {
        let g = fence_data_disk(&dd, &ls, &hid, project_id).await?;
        config.data_disk_path = Some(g.device());
        Some(g)
    } else {
        None
    };

    // From here, any `?` (restore/start/wait_for_agent failure) drops `disk_guard`,
    // which releases the lease + detaches the disk — so a failed wake never bricks the
    // project with a leaked lease.
    let vm = if let Some(ref meta) = snap_meta {
        let snap_path = PathBuf::from(&meta.snapshot_path);
        let mem_path = PathBuf::from(&meta.mem_file_path);
        if snap_path.exists() && mem_path.exists() {
            info!(project = %project_id, "restoring from snapshot");
            match VmInstance::restore_from_snapshot(
                project_id,
                &config,
                &runtime_dir,
                &snap_path,
                &mem_path,
            )
            .await
            {
                Ok(vm) => vm,
                Err(e) => {
                    tracing::warn!(project = %project_id, error = %e, "snapshot restore failed, cold booting");
                    // Clean up the failed restore's Firecracker process and socket
                    let failed_sock = runtime_dir.join(project_id).join("firecracker.sock");
                    if failed_sock.exists() {
                        let _ = tokio::fs::remove_file(&failed_sock).await;
                    }
                    // Kill any leftover Firecracker for this project
                    let _ = tokio::process::Command::new("pkill")
                        .args(["-f", &format!("firecracker.*{project_id}")])
                        .status()
                        .await;
                    tokio::time::sleep(Duration::from_millis(200)).await;
                    VmInstance::start(project_id, &config, &runtime_dir).await?
                }
            }
        } else {
            info!(project = %project_id, "snapshot files missing, cold booting");
            VmInstance::start(project_id, &config, &runtime_dir).await?
        }
    } else {
        info!(project = %project_id, "no snapshot, cold booting");
        VmInstance::start(project_id, &config, &runtime_dir).await?
    };

    wait_for_agent(&alloc.ip).await?;

    let mut plat = platform.lock().await;

    // Re-validate the project still exists before committing the VM. handle_teardown
    // waits out our `Waking` state, so a delete can't race the body above — but a
    // delete that landed BEFORE we set Waking would leave us booting a ghost. If so,
    // abort: dropping `vm` SIGKILLs the FC and dropping the armed `disk_guard` releases
    // the lease + disk.
    if plat.store.get_project(project_id).ok().flatten().is_none() {
        plat.vm_states.remove(project_id);
        anyhow::bail!("project {project_id} was deleted during wake; aborting");
    }

    // Record Firecracker's PID as the data-disk writer, then DISARM the guard and hold
    // the token for the VM's lifetime (released on hibernate/stop/teardown).
    if let Some(guard) = disk_guard {
        if let Some(pid) = vm.pid() {
            let dd2 = plat.data_disk.clone();
            let _ = dd2.set_writer_pid(project_id, guard.token(), pid).await;
        }
        plat.disk_tokens.insert(project_id.to_string(), guard.disarm());
    }
    plat.vms.insert(project_id.to_string(), vm);
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Running);

    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Active;
        plat.store.update_project(&proj)?;
    }
    drop(plat);

    register_active_routes(&routing, &domain_map, &active_domains, project_id, &alloc.ip).await;

    info!(project = %project_id, ip = %alloc.ip, "VM awake, routing active");
    Ok(alloc.ip)
}

async fn wait_for_route(
    project_id: &str,
    routing: &jkbase_proxy::RoutingTable,
) -> Result<String> {
    for _ in 0..150 {
        tokio::time::sleep(Duration::from_millis(200)).await;
        let table = routing.read().await;
        if let Some(ip) = table.get(project_id) {
            return Ok(ip.clone());
        }
    }
    anyhow::bail!("timed out waiting for {project_id} to wake");
}

async fn idle_detection_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    activity: ActivityTracker,
    idle_timeout: Duration,
    shipper: Arc<LogShipper>,
) {
    let check_interval = Duration::from_secs(60);

    loop {
        tokio::time::sleep(check_interval).await;

        // Seed a baseline for any Running VM the proxy hasn't tracked. Activity is
        // only recorded on proxy requests, so a project that receives none — e.g. a
        // cron-only function project, woken host->agent — would otherwise never be a
        // hibernation candidate and never scale to zero. Seeding `now` gives it an
        // idle clock that ages out after `idle_timeout` of no further activity.
        {
            let running: Vec<String> = {
                let plat = platform.lock().await;
                plat.vm_states
                    .iter()
                    .filter(|(_, s)| **s == VmLifecycle::Running)
                    .map(|(id, _)| id.clone())
                    .collect()
            };
            let mut tracker = activity.write().await;
            let now = Instant::now();
            for id in running {
                tracker.entry(id).or_insert(now);
            }
        }

        let candidates: Vec<String> = {
            let tracker = activity.read().await;
            let now = Instant::now();
            tracker
                .iter()
                .filter(|(_, last)| now.duration_since(**last) > idle_timeout)
                .map(|(id, _)| id.clone())
                .collect()
        };

        for project_id in candidates {
            let should_hibernate = {
                let plat = platform.lock().await;
                plat.vm_states.get(&project_id) == Some(&VmLifecycle::Running)
            };

            if should_hibernate {
                info!(project = %project_id, "idle timeout, hibernating");
                if let Err(e) = hibernate_project(
                    &project_id,
                    platform.clone(),
                    routing.clone(),
                    shipper.clone(),
                )
                .await
                {
                    tracing::error!(project = %project_id, error = %e, "failed to hibernate");
                }

                let mut tracker = activity.write().await;
                tracker.remove(&project_id);
            }
        }
    }
}

/// Periodically pull new guest logs from every running VM into the persistent
/// log store so they survive hibernation, restart, and crashes.
async fn log_shipper_loop(platform: Arc<Mutex<PlatformState>>, shipper: Arc<LogShipper>) {
    loop {
        tokio::time::sleep(log_shipper::POLL_INTERVAL).await;

        let targets: Vec<(String, String)> = {
            let plat = platform.lock().await;
            plat.vm_states
                .iter()
                .filter(|(_, s)| **s == VmLifecycle::Running)
                .filter_map(|(id, _)| {
                    plat.store
                        .get_vm_allocation(id)
                        .ok()
                        .flatten()
                        .map(|a| (id.clone(), a.ip))
                })
                .collect()
        };

        for (project_id, ip) in targets {
            shipper.ship(&project_id, &ip).await;
        }
    }
}

async fn setup_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if !exists {
        run_cmd("ip", &["tuntap", "add", "dev", tap_name, "mode", "tap"]).await?;
        run_cmd("ip", &["link", "set", tap_name, "master", "jkbr0"]).await?;
        run_cmd("ip", &["link", "set", tap_name, "up"]).await?;
        info!(tap_name, "tap device created");
    }

    Ok(())
}

async fn teardown_tap(tap_name: &str) -> Result<()> {
    let exists = tokio::process::Command::new("ip")
        .args(["link", "show", tap_name])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .await?
        .success();

    if exists {
        run_cmd("ip", &["link", "delete", tap_name]).await?;
        info!(tap_name, "tap device removed");
    }

    Ok(())
}

async fn run_cmd(cmd: &str, args: &[&str]) -> Result<()> {
    let status = tokio::process::Command::new(cmd)
        .args(args)
        .status()
        .await?;
    if !status.success() {
        anyhow::bail!("{} {:?} failed with {}", cmd, args, status);
    }
    Ok(())
}

/// Rename any legacy `{id}.ext4` data disks to LocalLoop's `{id}.img` convention so
/// existing per-project data is picked up by the loop-device-backed provider. File
/// contents are untouched; subsequent boots find no `.ext4` and no-op.
async fn migrate_legacy_data_disks(dir: &Path) -> Result<()> {
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return Ok(()), // dir absent → nothing to migrate
    };
    while let Some(entry) = rd.next_entry().await? {
        let p = entry.path();
        if p.extension().and_then(|e| e.to_str()) == Some("ext4") {
            let img = p.with_extension("img");
            if !tokio::fs::try_exists(&img).await.unwrap_or(false) {
                info!(from = %p.display(), to = %img.display(), "migrating legacy data disk to .img");
                tokio::fs::rename(&p, &img).await?;
            }
        }
    }
    Ok(())
}

/// Reap any Firecracker process still running for `project_id` (best-effort).
async fn reap_firecracker(project_id: &str) {
    let _ = tokio::process::Command::new("pkill")
        .args(["-f", &format!("firecracker.*{project_id}")])
        .status()
        .await;
}

/// RAII hold on a fenced data disk for a VM's **boot window**. [`fence_data_disk`]
/// returns it ARMED (lease acquired + disk attached). If it is dropped before
/// [`disarm`](DiskLeaseGuard::disarm) — i.e. the boot failed on any `?`
/// (`VmInstance::start`/`restore_from_snapshot`/`wait_for_agent`) — it asynchronously
/// detaches the disk + releases the lease, so a failed boot can NEVER leak the lease
/// (a leak would brick the project with `LeaseHeld`/`RwoUnsafe` until the server
/// restarts). On success the caller `disarm`s it and stores the token in `disk_tokens`
/// for teardown-time release.
struct DiskLeaseGuard {
    data_disk: Arc<dyn DataDiskProvider>,
    lease: Arc<dyn Lease>,
    project_id: String,
    token: FenceToken,
    device: PathBuf,
    armed: bool,
}

impl DiskLeaseGuard {
    fn device(&self) -> PathBuf {
        self.device.clone()
    }
    fn token(&self) -> &FenceToken {
        &self.token
    }
    /// Success path: stop auto-releasing and hand back the token to record in
    /// `disk_tokens` (which the teardown/hibernate paths release).
    fn disarm(mut self) -> FenceToken {
        self.armed = false;
        self.token.clone()
    }
}

impl Drop for DiskLeaseGuard {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        // Release asynchronously. Guard against being dropped outside a runtime (e.g.
        // during shutdown) so we never panic in Drop; the flock releases on process
        // exit anyway.
        let Ok(handle) = tokio::runtime::Handle::try_current() else {
            return;
        };
        warn!(project = %self.project_id, "data-disk boot guard dropped before activation — detaching + releasing lease");
        let (dd, ls, id, tok) = (
            self.data_disk.clone(),
            self.lease.clone(),
            self.project_id.clone(),
            self.token.clone(),
        );
        handle.spawn(async move {
            let _ = dd.detach(&id).await;
            let _ = ls.release(&tok).await;
        });
    }
}

/// Acquire the data-disk lease + attach the disk **read-write-once**, fencing any
/// prior writer, and return an armed [`DiskLeaseGuard`]. The armed guard is built the
/// instant `acquire` succeeds and OWNS the `ensure`/`attach` steps, so if those error
/// — OR the whole future is cancelled mid-attach (the wake/deploy callback is awaited
/// inline by the proxy, so a client disconnect cancels it) — the guard drops and
/// releases the lease. On `RwoUnsafe` (a prior writer still proven alive) it reaps a
/// stale Firecracker and retries once. After success the caller `disarm`s the guard.
async fn fence_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    host_id: &str,
    project_id: &str,
) -> Result<DiskLeaseGuard> {
    let token = lease
        .acquire(project_id, host_id, DISK_LEASE_TTL)
        .await
        .map_err(|e| anyhow::anyhow!("lease acquire for {project_id}: {e}"))?;
    // Armed BEFORE the slow ensure/attach: any error or cancellation from here drops
    // the guard (which detaches + releases the lease) — no acquire→attach leak.
    let mut guard = DiskLeaseGuard {
        data_disk: data_disk.clone(),
        lease: lease.clone(),
        project_id: project_id.to_string(),
        token,
        device: PathBuf::new(),
        armed: true,
    };
    let device = fence_attach(data_disk, project_id, guard.token()).await?;
    guard.device = device;
    Ok(guard)
}

async fn fence_attach(
    data_disk: &Arc<dyn DataDiskProvider>,
    project_id: &str,
    token: &FenceToken,
) -> Result<PathBuf> {
    data_disk
        .ensure(project_id, DATA_DISK_MIB * 1024 * 1024)
        .await
        .map_err(|e| anyhow::anyhow!("ensure data disk {project_id}: {e}"))?;
    let device = match data_disk.attach_rwo(project_id, token).await {
        Ok(d) => d,
        Err(SubstrateError::RwoUnsafe { .. }) => {
            warn!(project = %project_id, "data disk held by a live prior writer; reaping stale Firecracker and retrying attach");
            reap_firecracker(project_id).await;
            tokio::time::sleep(Duration::from_millis(300)).await;
            data_disk
                .attach_rwo(project_id, token)
                .await
                .map_err(|e| anyhow::anyhow!("attach_rwo after reap {project_id}: {e}"))?
        }
        Err(e) => return Err(anyhow::anyhow!("attach_rwo {project_id}: {e}")),
    };
    Ok(device.path)
}

/// Release a project's data disk: detach the device + release the lease so another
/// host/boot can acquire without waiting out the TTL. Best-effort (teardown path).
async fn release_data_disk(
    data_disk: &Arc<dyn DataDiskProvider>,
    lease: &Arc<dyn Lease>,
    project_id: &str,
    token: FenceToken,
) {
    let _ = data_disk.detach(project_id).await;
    let _ = lease.release(&token).await;
}

fn check_project_has_volumes(data_dir: &Path, project_id: &str) -> bool {
    let servers_dir = data_dir
        .join("hosting")
        .join(project_id)
        .join("live")
        .join("_servers");
    if !servers_dir.exists() {
        return false;
    }
    for entry in std::fs::read_dir(&servers_dir).into_iter().flatten() {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        if path.extension().is_some_and(|e| e == "json")
            && let Ok(content) = std::fs::read_to_string(&path)
                && content.contains("\"volumes\"") && content.contains("\"mount\"") {
                    return true;
                }
    }
    false
}

/// Application-level liveness probe. Returns true only if the agent answers HTTP
/// within the budget. A wedged agent (kernel up, userspace stuck) completes the
/// TCP handshake but never answers, so a bare TCP connect is NOT sufficient — we
/// must hit `/_jkbase/health` and bound it with a timeout.
async fn agent_alive(ip: &str) -> bool {
    let probe = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await.ok()?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await.ok()?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .uri(format!("http://{ip}:80/_jkbase/health"))
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())
            .ok()?;
        let resp = sender.send_request(req).await.ok()?;
        Some(resp.status().is_success())
    };
    matches!(
        tokio::time::timeout(Duration::from_secs(2), probe).await,
        Ok(Some(true))
    )
}

/// Centralized force-stop + state reconciliation for a project whose graceful
/// hibernate could not complete (wedged agent, pause/snapshot timeout, or error).
/// Idempotent and best-effort: every step is independently fallible-ignored so a
/// failure in one does not strand the others. After this runs the project is left
/// as Hibernated-with-no-snapshot, so the next request cold-boots cleanly.
async fn force_stop_and_cleanup(project_id: &str, platform: &Arc<Mutex<PlatformState>>) {
    let mut plat = platform.lock().await;

    // The VM handle may already be gone (hibernate_project removes it before the
    // pause that fails) — stop() it if present, but don't rely on it.
    if let Some(mut vm) = plat.vms.remove(project_id) {
        let _ = vm.stop().await;
    }
    // Release the data-disk hold so the next wake re-fences (the FC is reaped below).
    if let Some(token) = plat.disk_tokens.remove(project_id) {
        let dd = plat.data_disk.clone();
        let ls = plat.lease.clone();
        release_data_disk(&dd, &ls, project_id, token).await;
    }

    let alloc = plat.store.get_vm_allocation(project_id).ok().flatten();

    // Drop any snapshot meta so wake deterministically cold-boots rather than
    // trying to restore a stale or half-written snapshot.
    let _ = plat.store.remove_snapshot_meta(project_id);

    // Persisted state -> Hibernated keeps the project's domains routed so the next
    // request cold-boots cleanly (snapshot is gone, so wake falls through to boot).
    if let Ok(Some(mut proj)) = plat.store.get_project(project_id) {
        proj.state = ProjectState::Hibernated;
        let _ = plat.store.update_project(&proj);
    }

    // Never leave it stuck at Hibernating (shared with the idle loop — that would
    // make wake_project spin and bail on every subsequent request).
    plat.vm_states
        .insert(project_id.to_string(), VmLifecycle::Hibernated);

    drop(plat);

    // Guarantee the leaked Firecracker process dies even when `vms` had no handle.
    let _ = tokio::process::Command::new("pkill")
        .args(["-f", &format!("firecracker.*{project_id}")])
        .status()
        .await;

    // Tear down TAP so cleanup_orphans reconciles consistently on next boot (a
    // leaked-but-listening process would otherwise read as "reachable" and the
    // stale allocation would never be reaped). wake re-runs setup_tap.
    if let Some(a) = alloc {
        let _ = teardown_tap(&a.tap_device).await;
    }
}

use chrono::{TimeZone, Utc};
use cron::Schedule as CronSchedule;

/// Coarse fixed tick. 30s gives `*/1 * * * *` schedules <=30s firing latency.
const SCHED_TICK: Duration = Duration::from_secs(30);
/// Max simultaneous in-flight fires (each can wake a hibernated VM = seconds).
const MAX_CONCURRENT_FIRES: usize = 4;
/// Never replay further back than this after downtime; collapse backlog to one fire.
const CATCHUP_CAP_SECS: u64 = 3600;

/// Parse a 5-field UNIX cron. The `cron` crate is 6-field (field 0 = seconds), so
/// a standard 5-field expression is left-padded with "0 " to fire at second 0.
/// Must stay in sync with the deploy-time validation in jkbase-control.
fn parse_unix_5field(expr: &str) -> Result<CronSchedule, cron::error::Error> {
    use std::str::FromStr;
    CronSchedule::from_str(&format!("0 {expr}"))
}

/// Fire instants strictly after `last_run`, up to and including `now` (epoch secs).
fn due_since(sched: &CronSchedule, last_run: u64, now: u64) -> Vec<u64> {
    let Some(after) = Utc.timestamp_opt(last_run as i64, 0).single() else {
        return Vec::new();
    };
    sched
        .after(&after)
        .take_while(|t| t.timestamp() as u64 <= now)
        .map(|t| t.timestamp() as u64)
        .collect()
}

/// Host-driven cron loop. Reads the durable SCHEDULES registry each tick (the
/// single source of truth), computes occurrences due since each schedule's
/// last_run, and fires them — waking the project if hibernated. Gated, in future
/// HA, to projects this host owns; today single-host owns all.
async fn scheduler_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
    activity: ActivityTracker,
) {
    let sem = Arc::new(tokio::sync::Semaphore::new(MAX_CONCURRENT_FIRES));
    let in_flight: Arc<Mutex<HashSet<(String, String)>>> = Arc::new(Mutex::new(HashSet::new()));

    loop {
        tokio::time::sleep(SCHED_TICK).await;
        let now = jkbase_control::auth::timestamp();

        // Snapshot the registry under the lock, then release it before per-project
        // work (wake/invoke must not hold the platform lock).
        let schedules = {
            let plat = platform.lock().await;
            match plat.store.list_schedules() {
                Ok(s) => s,
                Err(e) => {
                    tracing::warn!(error = %e, "scheduler: failed to read schedules");
                    continue;
                }
            }
        };

        for sched in schedules {
            let Ok(parsed) = parse_unix_5field(&sched.cron) else {
                continue;
            };

            // Catch-up cap: clamp the replay origin so a long outage doesn't
            // stampede, and collapse any backlog to a single fire.
            let last = sched.last_run.unwrap_or(now);
            let effective_last = last.max(now.saturating_sub(CATCHUP_CAP_SECS));
            let due = due_since(&parsed, effective_last, now);
            let Some(&fire_at) = due.last() else {
                continue;
            };

            let key = (sched.project_id.clone(), sched.function.clone());
            {
                let mut inf = in_flight.lock().await;
                if !inf.insert(key.clone()) {
                    continue; // already firing from a previous tick
                }
            }

            let platform = platform.clone();
            let routing = routing.clone();
            let domain_map = domain_map.clone();
            let shipper = shipper.clone();
            let sem = sem.clone();
            let in_flight = in_flight.clone();
            let activity = activity.clone();

            tokio::spawn(async move {
                let _permit = sem.acquire_owned().await.unwrap();
                let result = fire_schedule(
                    &sched.project_id,
                    &sched.function,
                    platform.clone(),
                    routing,
                    domain_map,
                    shipper,
                )
                .await;

                match result {
                    Ok(()) => {
                        let plat = platform.lock().await;
                        let _ = plat.store.update_schedule_last_run(
                            &sched.project_id,
                            &sched.function,
                            fire_at,
                        );
                        drop(plat);
                        // Count the fire as activity so the project re-hibernates
                        // idle_timeout AFTER the last fire (frequent crons stay warm;
                        // sparse crons scale to zero between fires) rather than
                        // churning on the idle loop's seeded baseline.
                        activity
                            .write()
                            .await
                            .insert(sched.project_id.clone(), Instant::now());
                    }
                    Err(e) => {
                        // last_run unadvanced -> retried next tick (bounded by the cap).
                        tracing::error!(project = %sched.project_id, function = %sched.function,
                            error = %e, "scheduled invoke failed; will retry next tick");
                    }
                }
                in_flight.lock().await.remove(&key);
            });
        }
    }
}

/// Wake `project_id` if needed, then invoke `name` over plain HTTP. Lock-free
/// during the call (wake_project drops the platform lock before returning the IP).
async fn fire_schedule(
    project_id: &str,
    name: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    domain_map: DomainMap,
    shipper: Arc<LogShipper>,
) -> Result<()> {
    let ip = wake_project(project_id, platform, routing, domain_map, shipper)
        .await
        .map_err(|e| anyhow::anyhow!("wake failed: {e:?}"))?;

    let call = async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);
        let req = hyper::Request::builder()
            .method(hyper::Method::POST)
            .uri(format!("http://{ip}:80/functions/{name}"))
            .header("x-jkbase-trigger", "schedule")
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
        let resp = sender.send_request(req).await?;
        Ok::<_, anyhow::Error>(resp.status())
    };

    let status = match tokio::time::timeout(Duration::from_secs(30), call).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("scheduled fn {name} for {project_id} timed out"),
    };
    if !status.is_success() {
        anyhow::bail!("scheduled fn {name} returned {status}");
    }
    Ok(())
}

/// Sample interval. Coarse — usage is billed over hours, not seconds.
const METERING_TICK: Duration = Duration::from_secs(60);
/// Keep ~3 months of hourly buckets; prune older so month-to-date is never lost.
const USAGE_RETENTION_SECS: u64 = 90 * 86400;

/// Host-side metering + quota enforcement. Each tick: sample per-project CPU
/// (/proc), bandwidth (TAP /sys, delta-accumulated), and storage (on-disk), roll
/// them into the current hour bucket, then enforce the monthly bandwidth cap by
/// hibernating + flagging over-quota projects (the wake gate refuses to wake a
/// flagged project). All `/proc`,`/sys`,fs I/O happens with the platform lock
/// released (the log_shipper_loop idiom).
async fn metering_loop(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    shipper: Arc<LogShipper>,
) {
    let mut state = metering::SamplerState::default();
    let mut last_sample = Instant::now();
    let mut ticks: u64 = 0;

    loop {
        tokio::time::sleep(METERING_TICK).await;
        ticks += 1;
        let now = jkbase_control::auth::timestamp();
        let hour_epoch = now / 3600 * 3600;
        let elapsed = last_sample.elapsed().as_secs().max(1);
        last_sample = Instant::now();

        // Snapshot everything we need under one platform lock, then release it
        // before any /proc, /sys, or filesystem I/O.
        let (running_pids, allocs, projects, data_dir, store) = {
            let plat = platform.lock().await;
            let running_pids: Vec<(String, u32)> = plat
                .vm_states
                .iter()
                .filter(|(_, s)| **s == VmLifecycle::Running)
                .filter_map(|(id, _)| {
                    plat.vms.get(id).and_then(|vm| vm.pid()).map(|pid| (id.clone(), pid))
                })
                .collect();
            let allocs: Vec<(String, String)> = plat
                .store
                .list_vm_allocations()
                .unwrap_or_default()
                .into_iter()
                .map(|a| (a.project_id, a.tap_device))
                .collect();
            let projects: Vec<String> = plat
                .store
                .list_projects()
                .unwrap_or_default()
                .into_iter()
                .map(|p| p.id)
                .collect();
            (running_pids, allocs, projects, plat.data_dir.clone(), plat.store.clone())
        };

        // CPU deltas (only Running VMs have a live pid).
        let mut cpu: HashMap<String, u64> = HashMap::new();
        for (id, pid) in &running_pids {
            if let Some(cur) = metering::read_cpu_jiffies(*pid) {
                cpu.insert(id.clone(), state.cpu_delta(id, *pid, cur));
            }
        }
        // Bandwidth deltas from each project's TAP.
        let mut bw: HashMap<String, (u64, u64)> = HashMap::new();
        for (id, tap) in &allocs {
            if let Some((rx, tx)) = metering::read_tap_bytes(tap) {
                bw.insert(id.clone(), state.tap_delta(id, tap, rx, tx));
            }
        }

        // Roll each project's sample into its current hour bucket. Skip projects
        // with nothing to record (no storage, no deltas) to avoid empty rows.
        for id in &projects {
            let cpu_j = cpu.get(id).copied().unwrap_or(0);
            let (rx, tx) = bw.get(id).copied().unwrap_or((0, 0));
            let storage = jkbase_common::storage::project_storage_bytes(&data_dir, id);
            if cpu_j == 0 && rx == 0 && tx == 0 && storage == 0 {
                continue;
            }
            if let Err(e) = store.add_usage(id, hour_epoch, cpu_j, rx, tx, storage, elapsed) {
                tracing::warn!(project = %id, error = %e, "metering: add_usage failed");
            }
        }

        // --- Quota enforcement (monthly bandwidth cap) ---
        let month_start = month_start_epoch(now);
        for id in &projects {
            let cap = store.get_quota(id).map(|q| q.bandwidth_bytes_per_month).unwrap_or(u64::MAX);
            let mtd = store.sum_month_to_date(id, month_start).unwrap_or_default();
            let used = mtd.rx_bytes.saturating_add(mtd.tx_bytes);
            let status = store.get_quota_status(id).ok().flatten();
            let blocked = status.as_ref().map(|s| s.bandwidth_blocked).unwrap_or(false);

            if used > cap && !blocked {
                // Write the block FIRST (source of truth for the wake gate) so a
                // request racing the hibernate is refused, then hibernate.
                let _ = store.save_quota_status(&QuotaStatus {
                    project_id: id.clone(),
                    bandwidth_blocked: true,
                    blocked_reason: Some("monthly bandwidth cap exceeded".to_string()),
                    blocked_at: now,
                    blocked_month: month_start,
                });
                tracing::warn!(project = %id, used, cap, "bandwidth cap exceeded; hibernating + blocking wake");
                let is_running = {
                    platform.lock().await.vm_states.get(id) == Some(&VmLifecycle::Running)
                };
                if is_running
                    && let Err(e) =
                        hibernate_project(id, platform.clone(), routing.clone(), shipper.clone()).await
                    {
                        tracing::error!(project = %id, error = %e, "failed to hibernate over-quota project");
                    }
            } else if blocked {
                // Clear on month rollover (new period) or if usage is back under
                // cap (e.g. an admin raised the override).
                let stale_month =
                    status.as_ref().map(|s| s.blocked_month != month_start).unwrap_or(false);
                if stale_month || used <= cap {
                    let _ = store.save_quota_status(&QuotaStatus {
                        project_id: id.clone(),
                        bandwidth_blocked: false,
                        blocked_reason: None,
                        blocked_at: 0,
                        blocked_month: month_start,
                    });
                    tracing::info!(project = %id, "bandwidth block cleared");
                }
            }
        }

        // Prune old buckets roughly hourly (60 ticks * 60s).
        if ticks.is_multiple_of(60) {
            let cutoff_hour = now.saturating_sub(USAGE_RETENTION_SECS) / 3600 * 3600;
            if let Ok(n) = store.prune_usage(cutoff_hour)
                && n > 0 {
                    tracing::info!(pruned = n, "metering: pruned old usage buckets");
                }
        }
    }
}

async fn sync_agent(ip: &str) -> Result<()> {
    if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
        let io = hyper_util::rt::TokioIo::new(stream);
        if let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(io).await {
            tokio::spawn(conn);
            let req = hyper::Request::builder()
                .uri(format!("http://{ip}:80/_jkbase/sync"))
                .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;
            let _ = sender.send_request(req).await;
        }
    }
    Ok(())
}

async fn wait_for_agent(ip: &str) -> Result<()> {
    for i in 0..50 {
        if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
            drop(stream);
            info!(ip, attempts = i + 1, "agent is ready");
            return Ok(());
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    anyhow::bail!("agent at {ip} did not become ready within 10 seconds");
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cron_parse_5field_and_due_since() {
        // 5-field UNIX cron parses (via the "0 " seconds shim); junk + wrong
        // arity do not.
        assert!(parse_unix_5field("*/5 * * * *").is_ok());
        assert!(parse_unix_5field("0 9 * * *").is_ok());
        assert!(parse_unix_5field("not a cron").is_err());
        assert!(parse_unix_5field("*/5 * * *").is_err()); // only 4 fields

        // 2021-01-01T00:00:00Z. Occurrences are strictly AFTER last_run, so the
        // 00:00:00 instant itself is excluded.
        let base: u64 = 1_609_459_200;
        let due = due_since(&parse_unix_5field("*/5 * * * *").unwrap(), base, base + 12 * 60);
        assert_eq!(due, vec![base + 5 * 60, base + 10 * 60]);
        // The loop fires only the latest (collapse-to-one catch-up).
        assert_eq!(due.last().copied(), Some(base + 10 * 60));

        // Window with no occurrence yields nothing (a daily cron over one minute).
        let none = due_since(&parse_unix_5field("0 0 * * *").unwrap(), base, base + 60);
        assert!(none.is_empty());
    }
}
