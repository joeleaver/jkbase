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
        rootfs_path: base.join("test-rootfs.ext4"),
        vcpu_count: 1,
        mem_size_mib: 128,
        tap_device: None,
        guest_mac: None,
        vsock_cid: None,
    };

    let runtime_dir = base.join("run");

    println!("Booting VM...");
    let mut vm = VmInstance::start("test-vm", &config, &runtime_dir).await?;
    println!("VM booted! Socket at: {}", vm.socket_path().display());
    println!("Press Ctrl+C to stop...");

    tokio::signal::ctrl_c().await?;

    println!("Stopping VM...");
    vm.stop().await?;
    println!("Done.");

    Ok(())
}
