use jkbase_orch::vm::{VmConfig, VmInstance};
use std::path::PathBuf;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".firecracker");

    let config = VmConfig {
        firecracker_bin: base.join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: base.join("vmlinux.bin"),
        rootfs_path: base.join("jkbase-rootfs.ext4"),
        metadata_image_path: None,
        layer_paths: Vec::new(),
        data_disk_path: None,
        vcpu_count: 1,
        mem_size_mib: 128,
        tap_device: Some("tap0".to_string()),
        guest_mac: Some("AA:FC:00:00:00:01".to_string()),
        guest_ip: Some("172.16.0.2".to_string()),
        gateway_ip: Some("172.16.0.1".to_string()),
        vsock_cid: None,
    };

    let runtime_dir = base.join("run");

    println!("Booting VM...");
    let mut vm = VmInstance::start("test-vm", &config, &runtime_dir).await?;
    println!("VM booted! Socket at: {}", vm.socket_path().display());
    println!();
    println!("Try: curl http://172.16.0.2/");
    println!();
    println!("Press Ctrl+C to stop...");

    tokio::signal::ctrl_c().await?;

    println!("Stopping VM...");
    vm.stop().await?;
    println!("Done.");

    Ok(())
}
