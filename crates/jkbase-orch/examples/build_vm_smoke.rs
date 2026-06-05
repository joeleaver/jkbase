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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));

    let cfg = BuildVmConfig {
        jailer_bin: fc_dir.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: fc_dir.join("firecracker-v1.15.1-x86_64"),
        kernel_path: data.join("vmlinux.bin"),
        toolchain_rootfs: data.join("toolchain.ext4"),
        source_drive: data.join("source.ext4"),
        scratch_size_bytes: 64 * 1024 * 1024,
        output_drive: data.join("output.ext4"),
        output_size_bytes: 16 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: 1,
        mem_size_mib: 256,
        vsock_cid: None,
        timeout: Duration::from_secs(30),
        chroot_base: data.join("jailer"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100000,
        gid: 100000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: 512,
        cgroup_mem_max_bytes: 512 * 1024 * 1024,
        cgroup_cpu_max: "100000 100000".to_string(),
        fsize_limit_bytes: None,
        console_log_max_bytes: 16 * 1024 * 1024,
        seccomp_filter: None,
        netns: None,
    };

    let runtime_dir = data.join("run");
    println!("calling BuildVm::run …");
    let outcome = BuildVm::run("smoke1", &cfg, &runtime_dir).await?;
    println!("OUTCOME: {outcome:?}");
    Ok(())
}
