//! On-box validation for the restore-path fence's Firecracker mechanism: a data
//! disk is loop-bound and cold-booted onto /dev/vdc, the VM is hibernated, then the
//! SAME image is re-bound to a DIFFERENT loop device and the VM is restored — which
//! exercises the new `load_snapshot(resume=false)` -> `patch_drive("data", …)` ->
//! `resume_vm` path. If the restored guest would re-derive the RW data drive from
//! the snapshot (the old behaviour) it would point at the stale device; this proves
//! it instead binds to the freshly-attached one and resumes.
//!
//! Doubles as the WS0 guest-kernel gauntlet: the cold-boot -> Full-snapshot ->
//! load(paused) -> patch_drive -> resume sequence is exactly the kernel-version-
//! sensitive path, so pointing `KERNEL` at a bumped kernel validates that the new
//! kernel can be snapshotted and restored under Firecracker before it is adopted.
//!
//! Needs root (losetup) + /dev/kvm. Run (KERNEL defaults to vmlinux.bin):
//!   cargo build -p jkbase-orch --example restore_fence_smoke
//!   sudo ./target/debug/examples/restore_fence_smoke
//!   sudo env KERNEL=vmlinux-6.12.92.bin ./target/debug/examples/restore_fence_smoke

use jkbase_orch::vm::{VmConfig, VmInstance};
use std::path::PathBuf;
use std::time::Duration;

async fn run(cmd: &str, args: &[&str]) -> anyhow::Result<String> {
    let out = tokio::process::Command::new(cmd).args(args).output().await?;
    if !out.status.success() {
        anyhow::bail!("{cmd} {args:?} failed: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".firecracker");
    // Kernel under test (WS0 gauntlet): default keeps the historical runtime kernel.
    let kernel = std::env::var("KERNEL").unwrap_or_else(|_| "vmlinux.bin".to_string());
    println!("[cfg] kernel = {}", base.join(&kernel).display());
    let work = std::env::temp_dir().join(format!("restore-fence-smoke-{}", std::process::id()));
    tokio::fs::create_dir_all(&work).await?;
    let data_img = work.join("data.ext4");
    let runtime_dir = work.join("run");

    // 1. Create + format a 16 MiB data disk image.
    run("dd", &["if=/dev/zero", &format!("of={}", data_img.display()), "bs=1M", "count=16"]).await?;
    run("mkfs.ext4", &["-F", "-q", data_img.to_str().unwrap()]).await?;

    let mk_config = |dev: &str| VmConfig {
        firecracker_bin: base.join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64"),
        kernel_path: base.join(&kernel),
        // Generic rootfs that boots to a console and stays alive (the jkbase rootfs
        // init exits without the full platform), so we have a stable VM to snapshot.
        rootfs_path: base.join("bionic.rootfs.ext4"),
        content_image_path: None,
        data_disk_path: Some(PathBuf::from(dev)),
        vcpu_count: 1,
        mem_size_mib: 128,
        tap_device: None,
        guest_mac: None,
        guest_ip: None,
        gateway_ip: None,
        vsock_cid: None,
    };

    // 2. Loop-bind the image (device A) and cold-boot with the data disk on /dev/vdc.
    let loop_a = run("losetup", &["--find", "--show", data_img.to_str().unwrap()]).await?;
    println!("[cold] data disk bound at {loop_a}");
    let mut vm = VmInstance::start("rf-smoke", &mk_config(&loop_a), &runtime_dir).await?;
    println!("[cold] boot OK, FC pid {:?}", vm.pid());
    tokio::time::sleep(Duration::from_secs(6)).await; // let the guest come up

    // 3. Hibernate (pause + snapshot + kill FC).
    let (snap, mem) = vm.hibernate(&work.join("snap")).await?;
    println!("[snap] snapshot={} mem={}", snap.display(), mem.display());

    // 4. Bind the SAME image to a DIFFERENT loop device (a relocated host device):
    //    bind the new one FIRST (so it gets a fresh number) then free the old, and
    //    restore — load paused, patch the data drive to loop_b, resume.
    let loop_b = run("losetup", &["--find", "--show", data_img.to_str().unwrap()]).await?;
    run("losetup", &["-d", &loop_a]).await?;
    assert_ne!(loop_a, loop_b, "expected a different loop device on restore");
    println!("[restore] re-bound at {loop_b}; restoring with data drive patched...");
    let mut vm2 =
        VmInstance::restore_from_snapshot("rf-smoke", &mk_config(&loop_b), &runtime_dir, &snap, &mem)
            .await?;
    println!("[restore] RESTORE OK, FC pid {:?}", vm2.pid());
    assert!(vm2.pid().is_some(), "restored VM must be running");
    tokio::time::sleep(Duration::from_secs(2)).await;
    assert!(vm2.pid().is_some(), "restored VM must still be running after resume");

    // 5. Cleanup.
    vm2.stop().await?;
    let _ = run("losetup", &["-d", &loop_b]).await;
    let _ = tokio::fs::remove_dir_all(&work).await;
    println!(
        "\n✅ restore-fence FC mechanism validated: cold boot + hibernate + restore \
         with the data drive patched to a DIFFERENT loop device — VM resumed."
    );
    Ok(())
}
