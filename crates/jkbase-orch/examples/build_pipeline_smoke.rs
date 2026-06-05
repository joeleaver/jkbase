//! On-box validation of the per-target build path the server orchestrator drives
//! (`build_orchestrator::build_one_target_inner`): build the RO source drive from
//! a directory, boot a jailed build VM on a real toolchain image, let the
//! build-runner run the source's `build.sh` under the CoW overlay, then read the
//! artifact back from the output drive via debugfs (no mount; threat-model P0-3).
//!
//! Needs KVM + root (jailer), so it can't run in CI. Build unprivileged, run via
//! sudo (mirrors `build_vm_smoke`):
//!
//!   cargo build -p jkbase-orch --example build_pipeline_smoke
//!   sudo env DATA=/tmp/jkb-bp FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/.firecracker/toolchains/default.ext4 \
//!       SOURCE_DIR=/abs/fixtures/fn ./target/debug/examples/build_pipeline_smoke
//!
//! Expects the parent cgroup `<cgroup_mount>/jkbase-build` to be provisioned with
//! `+pids +memory +cpu` delegated (the harness script does this). Asserts the
//! build exits 0 and a non-empty `/function.wasm` is extracted.

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let toolchain = PathBuf::from(std::env::var("TOOLCHAIN").expect("set TOOLCHAIN"));
    let source_dir = PathBuf::from(std::env::var("SOURCE_DIR").expect("set SOURCE_DIR"));
    let release = fc_dir.join("release-v1.15.1-x86_64");

    std::fs::create_dir_all(&data)?;
    let workspace = data.join("ws");
    std::fs::create_dir_all(&workspace)?;
    let source_img = workspace.join("function-app.source.img");
    let output_img = workspace.join("function-app.output.img");

    println!("[1/3] building RO source drive from {} (no mount) ...", source_dir.display());
    build_ro_ext4_from_dir(&source_dir, &source_img, 16)?;

    let cfg = BuildVmConfig {
        jailer_bin: release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: data.join("vmlinux.bin"),
        toolchain_rootfs: toolchain,
        source_drive: source_img.clone(),
        scratch_size_bytes: 256 * 1024 * 1024,
        output_drive: output_img.clone(),
        output_size_bytes: 64 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: 1,
        mem_size_mib: 512,
        vsock_cid: None,
        timeout: Duration::from_secs(60),
        chroot_base: data.join("build-jail"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100_000,
        gid: 100_000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: 512,
        cgroup_mem_max_bytes: 512 * 1024 * 1024,
        cgroup_cpu_max: "100000 100000".to_string(),
        fsize_limit_bytes: Some(64 * 1024 * 1024),
        console_log_max_bytes: 1024 * 1024,
        seccomp_filter: None,
        netns: None,
        tap_device: None,
        guest_mac: None,
        guest_ip: None,
        gateway_ip: None,
        egress_proxy: None,
        fetch_deadline: Duration::from_secs(120),
        seal: None,
    };

    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!("[2/3] booting jailed build VM (timeout {}s) ...", cfg.timeout.as_secs());
    let run = BuildVm::run("bp-smoke", &cfg, &data.join("run")).await?;
    let outcome = run.outcome;
    println!("    outcome: {outcome:?} (cpu={:?}us wall={:?})", run.cpu_usec, run.wall);

    if let Some(log) = build_output::read_capped(&output_img, "/build.log", 8 * 1024)? {
        println!("    --- build.log ---\n{}", String::from_utf8_lossy(&log).trim_end());
    }
    if outcome != BuildOutcome::Completed {
        anyhow::bail!("build VM did not complete cleanly: {outcome:?}");
    }

    println!("[3/3] reading artifacts back from output drive via debugfs (no mount) ...");
    let status = build_output::read_status(&output_img)?;
    println!("    status (build exit code): {status:?}");
    if status != Some(0) {
        anyhow::bail!("build script exited non-zero: {status:?}");
    }

    let wasm_out = workspace.join("function.wasm");
    let present = build_output::dump_file(&output_img, "/function.wasm", &wasm_out)?;
    if !present {
        anyhow::bail!("no /function.wasm artifact on the output drive");
    }
    let bytes = std::fs::read(&wasm_out)?;
    println!("    extracted /function.wasm: {} bytes", bytes.len());
    if bytes.len() < 8 || &bytes[..4] != b"\0asm" {
        anyhow::bail!("extracted artifact is not a wasm module (bad magic)");
    }

    println!("\nPASS: source -> build VM -> artifact read-back works end-to-end.");
    Ok(())
}
