use anyhow::Result;
use clap::Parser;
use jkbase_control::api::{self, AppState};
use jkbase_control::store::{Store, VmAllocation};
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::{self, new_routing_table};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::sync::Mutex;
use tracing::info;

#[derive(Parser)]
#[command(name = "jkbase-server", about = "jkbase platform server")]
struct Args {
    /// Data directory for platform state
    #[arg(long, default_value = "/var/jkbase")]
    data_dir: PathBuf,

    /// Directory containing Firecracker binaries and kernel
    #[arg(long)]
    fc_dir: PathBuf,

    /// Path to the musl-built jkbase-agent binary
    #[arg(long)]
    agent_bin: PathBuf,

    /// Port for the control plane API
    #[arg(long, default_value = "9090")]
    api_port: u16,

    /// Port for the proxy
    #[arg(long, default_value = "8080")]
    proxy_port: u16,
}

struct PlatformState {
    vms: HashMap<String, VmInstance>,
    store: Store,
    firecracker_bin: PathBuf,
    kernel_path: PathBuf,
    agent_bin: PathBuf,
    data_dir: PathBuf,
}

impl PlatformState {
    fn allocate_ip(&self) -> Result<(String, String, String)> {
        let existing = self.store.list_vm_allocations()?;
        let used_octets: HashSet<u8> = existing
            .iter()
            .filter_map(|a| a.ip.split('.').last()?.parse::<u8>().ok())
            .collect();

        // Allocate from 172.16.0.2 through 172.16.0.254
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
    tracing_subscriber::fmt::init();

    let args = Args::parse();

    tokio::fs::create_dir_all(&args.data_dir).await?;

    let db_path = args.data_dir.join("jkbase.redb");
    let deploy_dir = args.data_dir.join("hosting");
    tokio::fs::create_dir_all(&deploy_dir).await?;

    let store = Store::open(&db_path)?;
    let routing_table = new_routing_table();

    // Restore routing table from persisted allocations
    let existing_allocs = store.list_vm_allocations()?;
    if !existing_allocs.is_empty() {
        let mut table = routing_table.write().await;
        for alloc in &existing_allocs {
            info!(
                project = %alloc.project_id,
                ip = %alloc.ip,
                "restoring route from persisted allocation"
            );
            table.insert(alloc.project_id.clone(), alloc.ip.clone());
        }
    }

    let platform = Arc::new(Mutex::new(PlatformState {
        vms: HashMap::new(),
        store: store.clone(),
        firecracker_bin: args
            .fc_dir
            .join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: args.fc_dir.join("vmlinux.bin"),
        agent_bin: args.agent_bin,
        data_dir: args.data_dir,
    }));

    let mut state = AppState::new(store, deploy_dir);

    let platform_for_cb = platform.clone();
    let routing_for_cb = routing_table.clone();
    state.deploy_callback = Some(Box::new(move |project_id: String, _version: u64| {
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        Box::pin(async move { handle_deploy(&project_id, platform, routing).await })
    }));

    let state = Arc::new(state);
    let router = api::router(state);

    let proxy_port = args.proxy_port;
    let proxy_routes = routing_table.clone();
    tokio::spawn(async move {
        if let Err(e) = jkbase_proxy::serve(proxy_port, proxy_routes).await {
            tracing::error!(error = %e, "proxy error");
        }
    });

    // Clean up orphaned state from a previous crash
    cleanup_orphans(&platform).await;

    let addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        api = %addr,
        proxy = %format!("0.0.0.0:{proxy_port}"),
        "jkbase-server listening"
    );

    let platform_for_shutdown = platform.clone();
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal(platform_for_shutdown))
        .await?;

    Ok(())
}

async fn shutdown_signal(platform: Arc<Mutex<PlatformState>>) {
    tokio::signal::ctrl_c()
        .await
        .expect("failed to listen for ctrl-c");
    info!("shutdown signal received, stopping VMs...");

    let mut plat = platform.lock().await;
    let project_ids: Vec<String> = plat.vms.keys().cloned().collect();

    for project_id in &project_ids {
        if let Some(mut vm) = plat.vms.remove(project_id) {
            info!(project = %project_id, "stopping VM");
            if let Err(e) = vm.stop().await {
                tracing::error!(project = %project_id, error = %e, "failed to stop VM");
            }
        }

        if let Ok(Some(alloc)) = plat.store.get_vm_allocation(project_id) {
            let _ = teardown_tap(&alloc.tap_device).await;
            let _ = plat.store.remove_vm_allocation(project_id);
        }
    }

    info!("all VMs stopped, shutdown complete");
}

async fn cleanup_orphans(platform: &Arc<Mutex<PlatformState>>) {
    let plat = platform.lock().await;
    let allocs = match plat.store.list_vm_allocations() {
        Ok(a) => a,
        Err(_) => return,
    };

    for alloc in &allocs {
        // Check if the VM's agent is actually reachable
        let reachable = tokio::net::TcpStream::connect(format!("{}:80", alloc.ip))
            .await
            .is_ok();

        if !reachable {
            info!(
                project = %alloc.project_id,
                ip = %alloc.ip,
                "cleaning up orphaned allocation (VM not reachable)"
            );
            let _ = teardown_tap(&alloc.tap_device).await;
            let _ = plat.store.remove_vm_allocation(&alloc.project_id);
        }
    }
}

async fn handle_deploy(
    project_id: &str,
    platform: Arc<Mutex<PlatformState>>,
    routing: jkbase_proxy::RoutingTable,
) -> Result<()> {
    let mut plat = platform.lock().await;

    if let Some(mut old_vm) = plat.vms.remove(project_id) {
        info!(project = %project_id, "stopping old VM for redeploy");
        old_vm.stop().await?;
    }

    let content_dir = plat.data_dir.join("hosting").join(project_id).join("live");
    if !content_dir.exists() {
        anyhow::bail!("no deployed content for project {project_id}");
    }

    let rootfs_dir = plat.data_dir.join("rootfs");
    tokio::fs::create_dir_all(&rootfs_dir).await?;
    let rootfs_path = rootfs_dir.join(format!("{project_id}.ext4"));

    rootfs::build_rootfs(&plat.agent_bin, &content_dir, &rootfs_path, 64).await?;

    // Reuse existing allocation or create a new one
    let alloc = match plat.store.get_vm_allocation(project_id)? {
        Some(existing) => {
            info!(
                project = %project_id,
                ip = %existing.ip,
                "reusing persisted IP allocation"
            );
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
            info!(
                project = %project_id,
                ip = %alloc.ip,
                tap = %alloc.tap_device,
                "allocated new IP"
            );
            alloc
        }
    };

    setup_tap(&alloc.tap_device).await?;

    let config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path,
        vcpu_count: 1,
        mem_size_mib: 128,
        tap_device: Some(alloc.tap_device.clone()),
        guest_mac: Some(alloc.mac.clone()),
        guest_ip: Some(alloc.ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };

    let runtime_dir = plat.data_dir.join("run");
    let vm = VmInstance::start(project_id, &config, &runtime_dir).await?;

    plat.vms.insert(project_id.to_string(), vm);
    drop(plat);

    wait_for_agent(&alloc.ip).await?;

    {
        let mut table = routing.write().await;
        table.insert(project_id.to_string(), alloc.ip.clone());
    }

    info!(project = %project_id, ip = %alloc.ip, "VM ready, routing active");
    Ok(())
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

async fn wait_for_agent(ip: &str) -> Result<()> {
    for i in 0..50 {
        if let Ok(stream) = tokio::net::TcpStream::connect(format!("{ip}:80")).await {
            drop(stream);
            info!(ip, attempts = i + 1, "agent is ready");
            return Ok(());
        }
        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
    }
    anyhow::bail!("agent at {ip} did not become ready within 10 seconds");
}
