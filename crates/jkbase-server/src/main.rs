use anyhow::Result;
use clap::Parser;
use jkbase_control::api::{self, AppState};
use jkbase_control::store::Store;
use jkbase_orch::rootfs;
use jkbase_orch::vm::{VmConfig, VmInstance};
use jkbase_proxy::{self, new_routing_table};
use std::collections::HashMap;
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
    firecracker_bin: PathBuf,
    kernel_path: PathBuf,
    agent_bin: PathBuf,
    data_dir: PathBuf,
    next_ip_octet: u8,
}

impl PlatformState {
    fn next_vm_ip(&mut self) -> (String, String) {
        let octet = self.next_ip_octet;
        self.next_ip_octet += 1;
        let guest_ip = format!("172.16.0.{octet}");
        let tap_name = format!("tap{}", octet - 2);
        (guest_ip, tap_name)
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

    let platform = Arc::new(Mutex::new(PlatformState {
        vms: HashMap::new(),
        firecracker_bin: args
            .fc_dir
            .join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: args.fc_dir.join("vmlinux.bin"),
        agent_bin: args.agent_bin,
        data_dir: args.data_dir,
        next_ip_octet: 2,
    }));

    let mut state = AppState::new(store, deploy_dir);

    let platform_for_cb = platform.clone();
    let routing_for_cb = routing_table.clone();
    state.deploy_callback = Some(Box::new(move |project_id: &str, _version: u64| {
        let project_id = project_id.to_string();
        let platform = platform_for_cb.clone();
        let routing = routing_for_cb.clone();
        tokio::spawn(async move {
            if let Err(e) = handle_deploy(&project_id, platform, routing).await {
                tracing::error!(project = %project_id, error = %e, "deploy VM setup failed");
            }
        });
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

    let addr = SocketAddr::from(([0, 0, 0, 0], args.api_port));
    let listener = tokio::net::TcpListener::bind(addr).await?;
    info!(
        api = %addr,
        proxy = %format!("0.0.0.0:{proxy_port}"),
        "jkbase-server listening"
    );

    axum::serve(listener, router).await?;

    Ok(())
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

    let (guest_ip, tap_name) = plat.next_vm_ip();
    setup_tap(&tap_name).await?;

    let config = VmConfig {
        firecracker_bin: plat.firecracker_bin.clone(),
        kernel_path: plat.kernel_path.clone(),
        rootfs_path,
        vcpu_count: 1,
        mem_size_mib: 128,
        tap_device: Some(tap_name),
        guest_mac: Some(format!("AA:FC:00:00:00:{:02X}", plat.next_ip_octet - 1)),
        guest_ip: Some(guest_ip.clone()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };

    let runtime_dir = plat.data_dir.join("run");
    let vm = VmInstance::start(project_id, &config, &runtime_dir).await?;

    plat.vms.insert(project_id.to_string(), vm);
    drop(plat);

    wait_for_agent(&guest_ip).await?;

    {
        let mut table = routing.write().await;
        table.insert(project_id.to_string(), guest_ip.clone());
    }

    info!(project = %project_id, ip = %guest_ip, "VM ready, routing active");
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
