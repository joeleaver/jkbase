mod log_shipper;
mod metering;

use anyhow::Result;
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
use tracing::info;

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
}

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

#[tokio::main]
async fn main() -> Result<()> {
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("failed to install rustls crypto provider");

    tracing_subscriber::fmt::init();

    let args = Args::parse();
    let data_dir = args.data_dir.clone();

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

    let platform = Arc::new(Mutex::new(PlatformState {
        vms: HashMap::new(),
        vm_states: HashMap::new(),
        store: store.clone(),
        firecracker_bin: args
            .fc_dir
            .join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: args.fc_dir.join("vmlinux.bin"),
        base_rootfs_path,
        data_dir: data_dir.clone(),
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

    let mut state = AppState::new(store, log_store.clone(), deploy_dir);
    state.routing_table = Some(routing_table.clone());
    state.domain_map = Some(domain_map.clone());
    state.platform_domain = args.domain.clone();
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
    cleanup_orphans(&platform).await;
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
        old_vm.stop().await?;
    }

    let content_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    if !content_dir.exists() {
        anyhow::bail!("no deployed content for project {project_id}");
    }

    let content_images_dir = plat.data_dir.join("content-images");
    tokio::fs::create_dir_all(&content_images_dir).await?;
    let content_image_path = content_images_dir.join(format!("{project_id}.ext4"));

    rootfs::build_content_image(&content_dir, &content_image_path).await?;

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

    setup_tap(&alloc.tap_device).await?;

    // Create data disk for persistent volumes if any servers declare volumes
    let data_disk_path = {
        let data_disks_dir = plat.data_dir.join("data-disks");
        let disk_path = data_disks_dir.join(format!("{project_id}.ext4"));
        let has_volumes = check_project_has_volumes(&plat.data_dir, project_id);
        if has_volumes {
            tokio::fs::create_dir_all(&data_disks_dir).await?;
            rootfs::create_data_disk(&disk_path, 1024).await?;
            Some(disk_path)
        } else if disk_path.exists() {
            Some(disk_path)
        } else {
            None
        }
    };

    let config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path: plat.base_rootfs_path.clone(),
        content_image_path: Some(content_image_path),
        data_disk_path,
        vcpu_count: 1,
        mem_size_mib: 1024,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };

    let runtime_dir = plat.data_dir.join("run");
    let vm = VmInstance::start(project_id, &config, &runtime_dir).await?;

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
    let meta = SnapshotMeta {
        project_id: project_id.to_string(),
        snapshot_path: snapshot_path.to_string_lossy().to_string(),
        mem_file_path: mem_file_path.to_string_lossy().to_string(),
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        vcpu_count: 1,
        mem_size_mib: 1024,
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

    let content_image_path = plat
        .data_dir
        .join("content-images")
        .join(format!("{project_id}.ext4"));

    let data_disk_path = {
        let disk = plat.data_dir.join("data-disks").join(format!("{project_id}.ext4"));
        if disk.exists() { Some(disk) } else { None }
    };

    let config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path: plat.base_rootfs_path.clone(),
        content_image_path: Some(content_image_path),
        data_disk_path,
        vcpu_count: 1,
        mem_size_mib: 1024,
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
