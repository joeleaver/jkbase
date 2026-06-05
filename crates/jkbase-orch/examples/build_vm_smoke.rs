//! On-box smoke test for the jailed build-VM lifecycle. NOT a unit test — it
//! needs KVM + root (jailer), so it can't run in CI. Build as an unprivileged
//! user, then run the resulting binary under sudo:
//!
//!   cargo build -p jkbase-orch --example build_vm_smoke
//!   sudo env DATA=/tmp/jkb-bvm FC_DIR=/abs/.firecracker/release-v1.15.1-x86_64 \
//!       ./target/debug/examples/build_vm_smoke
//!
//! Expects, under $DATA (all one filesystem, same as chroot_base):
//!   vmlinux.bin, toolchain.ext4 (bootable, RO), source.ext4 (RO)
//! Prints the BuildOutcome and leaves $DATA/output.ext4 (moved out of the jail).

use jkbase_orch::build_vm::{BuildVm, BuildVmConfig};
use std::path::PathBuf;
use std::time::Duration;

fn env_or<T: std::str::FromStr>(k: &str, default: T) -> T {
    std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(default)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let id = std::env::var("ID").unwrap_or_else(|_| "smoke1".to_string());
    let toolchain = std::env::var("TOOLCHAIN").unwrap_or_else(|_| "toolchain.ext4".to_string());

    let cfg = BuildVmConfig {
        jailer_bin: fc_dir.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: fc_dir.join("firecracker-v1.15.1-x86_64"),
        kernel_path: data.join("vmlinux.bin"),
        toolchain_rootfs: data.join(&toolchain),
        source_drive: data.join("source.ext4"),
        scratch_size_bytes: 64 * 1024 * 1024,
        output_drive: data.join("output.ext4"),
        output_size_bytes: 16 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: env_or("VCPUS", 1),
        mem_size_mib: env_or("MEM_MIB", 256),
        vsock_cid: None,
        timeout: Duration::from_secs(env_or("TIMEOUT_SECS", 30)),
        chroot_base: data.join("jailer"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100000,
        gid: 100000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: env_or("CGROUP_PIDS_MAX", 512),
        cgroup_mem_max_bytes: env_or("CGROUP_MEM_MAX", 512 * 1024 * 1024),
        cgroup_cpu_max: std::env::var("CGROUP_CPU_MAX").unwrap_or_else(|_| "100000 100000".to_string()),
        fsize_limit_bytes: None,
        console_log_max_bytes: 16 * 1024 * 1024,
        seccomp_filter: None,
        netns: None,
    };

    let runtime_dir = data.join("run");
    println!(
        "BuildVm::run id={id} mem={}MiB cgroup_mem_max={}B cpu.max=\"{}\" pids.max={} …",
        cfg.mem_size_mib, cfg.cgroup_mem_max_bytes, cfg.cgroup_cpu_max, cfg.cgroup_pids_max
    );
    let outcome = BuildVm::run(&id, &cfg, &runtime_dir).await?;
    println!("OUTCOME: {outcome:?}");
    Ok(())
}
