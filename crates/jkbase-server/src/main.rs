use anyhow::Result;
use clap::Parser;
use jkbase_control::api::{self, AppState};
use jkbase_control::store::{ProjectState, SnapshotMeta, Store, VmAllocation};
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::{self, new_routing_table, ActivityTracker, KnownProjects, ProxyConfig};
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
            .filter_map(|a| a.ip.split('.').last()?.parse::<u8>().ok())
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
    let routing_table = new_routing_table();
    let known_projects: KnownProjects = Arc::new(RwLock::new(HashSet::new()));
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

    let mut state = AppState::new(store, deploy_dir);
    state.routing_table = Some(routing_table.clone());

    let platform_for_cb = platform.clone();
    let routing_for_cb = routing_table.clone();
    let known_for_cb = known_projects.clone();
    state.deploy_callback = Some(Box::new(move |project_id: String, _version: u64| {
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        let known = known_for_cb.clone();
        Box::pin(async move { handle_deploy(&project_id, platform, routing, known).await })
    }));

    let state = Arc::new(state);
    let router = api::router(state, args.domain.clone());

    let tls_config = if args.tls {
        let cf_token = args
            .cloudflare_token
            .ok_or_else(|| anyhow::anyhow!("--cloudflare-token required when --tls is enabled"))?;
        let cf_zone = args
            .cloudflare_zone_id
            .ok_or_else(|| anyhow::anyhow!("--cloudflare-zone-id required when --tls is enabled"))?;
        let acme_email = args
            .acme_email
            .ok_or_else(|| anyhow::anyhow!("--acme-email required when --tls is enabled"))?;
        Some(jkbase_proxy::tls::TlsConfig {
            domain: args.domain.clone(),
            cert_dir: data_dir.join("certs"),
            cloudflare_token: cf_token,
            cloudflare_zone_id: cf_zone,
            acme_email,
        })
    } else {
        None
    };

    // Set up wake callback for the proxy
    let platform_for_wake = platform.clone();
    let routing_for_wake = routing_table.clone();
    let known_for_wake = known_projects.clone();
    let wake_callback: jkbase_proxy::WakeCallback =
        Arc::new(move |project_id: String| {
            let platform = platform_for_wake.clone();
            let routing = routing_for_wake.clone();
            let known = known_for_wake.clone();
            Box::pin(async move { wake_project(&project_id, platform, routing, known).await })
        });

    let api_addr = format!("127.0.0.1:{}", args.api_port);
    let proxy_config = ProxyConfig {
        http_port: args.proxy_port,
        https_port: if args.tls { Some(args.https_port) } else { None },
        platform_domain: args.domain,
        tls_config,
        api_addr: Some(api_addr),
        known_projects: Some(known_projects.clone()),
        activity_tracker: Some(activity_tracker.clone()),
        wake_callback: Some(wake_callback),
    };
    let proxy_port = proxy_config.http_port;
    let proxy_routes = routing_table.clone();
    tokio::spawn(async move {
        if let Err(e) = jkbase_proxy::serve(proxy_config, proxy_routes).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    cleanup_orphans(&platform).await;
    initialize_projects(&platform, &known_projects).await;

    // Spawn idle detection loop
    if args.idle_timeout_secs > 0 {
        let idle_timeout = Duration::from_secs(args.idle_timeout_secs);
        info!(timeout_secs = args.idle_timeout_secs, "idle detection enabled");
        tokio::spawn(idle_detection_loop(
            platform.clone(),
            routing_table.clone(),
            activity_tracker.clone(),
            idle_timeout,
        ));
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
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(platform_for_shutdown, routing_for_shutdown))
        .await?;

    Ok(())
}

async fn shutdown_signal(
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
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
        if let Err(e) = hibernate_project(project_id, platform.clone(), routing.clone()).await {
            tracing::error!(project = %project_id, error = %e, "hibernate failed, force stopping");
            let mut plat = platform.lock().await;
            if let Some(mut vm) = plat.vms.remove(project_id) {
                let _ = vm.stop().await;
            }
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
        let reachable = tokio::net::TcpStream::connect(format!("{}:80", alloc.ip))
            .await
            .is_ok();

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

async fn initialize_projects(
    platform: &Arc<Mutex<PlatformState>>,
    known_projects: &KnownProjects,
) {
    let projects = {
        let plat = platform.lock().await;
        match plat.store.list_projects() {
            Ok(p) => p,
            Err(e) => {
                tracing::error!(error = %e, "failed to list projects");
                return;
            }
        }
    };

    let mut kp = known_projects.write().await;
    let mut plat = platform.lock().await;

    for project in &projects {
        if project.current_version.is_none() {
            continue;
        }

        match project.state {
            ProjectState::Active | ProjectState::Hibernated => {
                kp.insert(project.id.clone());
                plat.vm_states
                    .insert(project.id.clone(), VmLifecycle::Hibernated);

                if project.state == ProjectState::Active {
                    let mut p = project.clone();
                    p.state = ProjectState::Hibernated;
                    let _ = plat.store.update_project(&p);
                }
            }
            ProjectState::Stopped => {}
        }
    }

    info!(count = kp.len(), "projects registered for on-demand wake");
}

async fn handle_deploy(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    known_projects: KnownProjects,
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
    let domains = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .map(|p| p.domains)
        .unwrap_or_default();
    drop(plat);

    wait_for_agent(&alloc.ip).await?;

    {
        let mut kp = known_projects.write().await;
        kp.insert(project_id.to_string());
    }
    {
        let mut table = routing.write().await;
        table.insert(project_id.to_string(), alloc.ip.clone());
        for domain in &domains {
            table.insert(domain.clone(), alloc.ip.clone());
            info!(project = %project_id, alias = %domain, "domain alias registered");
        }
    }

    info!(project = %project_id, ip = %alloc.ip, "VM ready, routing active");
    Ok(())
}

async fn hibernate_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
) -> Result<()> {
    let mut plat = platform.lock().await;

    match plat.vm_states.get(project_id) {
        Some(VmLifecycle::Running) => {
            plat.vm_states
                .insert(project_id.to_string(), VmLifecycle::Hibernating);
        }
        _ => anyhow::bail!("project {project_id} is not running"),
    }

    // Remove from routing table first (new requests will trigger wake)
    {
        let mut table = routing.write().await;
        table.remove(project_id);
        if let Ok(Some(proj)) = plat.store.get_project(project_id) {
            for domain in &proj.domains {
                table.remove(domain);
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
    drop(plat);

    let (snapshot_path, mem_file_path) = vm.hibernate(&snapshot_dir).await?;

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

async fn wake_project(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
    known_projects: KnownProjects,
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
                    return Box::pin(wake_project(
                        project_id,
                        platform.clone(),
                        routing,
                        known_projects,
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
            handle_deploy(project_id, platform, routing, known_projects).await?;
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
    let domains = plat
        .store
        .get_project(project_id)
        .ok()
        .flatten()
        .map(|p| p.domains)
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

    {
        let mut table = routing.write().await;
        table.insert(project_id.to_string(), alloc.ip.clone());
        for domain in &domains {
            table.insert(domain.clone(), alloc.ip.clone());
        }
    }

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
) {
    let check_interval = Duration::from_secs(60);

    loop {
        tokio::time::sleep(check_interval).await;

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
                if let Err(e) =
                    hibernate_project(&project_id, platform.clone(), routing.clone()).await
                {
                    tracing::error!(project = %project_id, error = %e, "failed to hibernate");
                }

                let mut tracker = activity.write().await;
                tracker.remove(&project_id);
            }
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
        if path.extension().is_some_and(|e| e == "json") {
            if let Ok(content) = std::fs::read_to_string(&path) {
                if content.contains("\"volumes\"") && content.contains("\"mount\"") {
                    return true;
                }
            }
        }
    }
    false
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
