//! On-box validation of **host-enforced fetch-then-seal** (design §9). Boots a
//! networked build VM whose `build.sh` tests connectivity to a host listener in
//! BOTH phases; the host seals the network (deletes the TAP) on the guest's
//! fetch-complete marker. Proves: network is UP during FETCH and DOWN during
//! COMPILE — and the guest cannot bring it back (the host owns the TAP).
//!
//! Needs KVM + root (jailer + `ip`). Build unprivileged, run via sudo:
//!
//!   cargo build -p jkbase-orch --example build_seal_smoke
//!   sudo env DATA=/abs/short/dir FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/short/dir/tc.ext4 ./target/debug/examples/build_seal_smoke
//!
//! DATA must hold `vmlinux.bin` + the toolchain on the same filesystem.

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig, SealFn};
use std::path::PathBuf;
use std::time::Duration;

const TAP: &str = "jkbtapseal";
const GW: &str = "172.30.0.1";
const GUEST: &str = "172.30.0.2";
const PORT: u16 = 9000;

async fn ip(args: &[&str]) {
    let _ = tokio::process::Command::new("ip").args(args).status().await;
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let toolchain = PathBuf::from(std::env::var("TOOLCHAIN").expect("set TOOLCHAIN"));
    let release = fc_dir.join("release-v1.15.1-x86_64");

    // Fixture: build.sh probes connectivity to the host listener in each phase.
    let src = data.join("seal-src");
    let _ = std::fs::remove_dir_all(&src);
    std::fs::create_dir_all(&src)?;
    std::fs::write(
        src.join("build.sh"),
        format!(
            r#"#!/bin/sh
probe() {{ if nc -w 2 {GW} {PORT} </dev/null >/dev/null 2>&1; then echo up; else echo down; fi; }}
case "${{1:-all}}" in
  fetch)   probe > /out/fetch-net ;;
  compile) probe > /out/compile-net; cp "$SRC/app.wasm" "$OUT/function.wasm" ;;
esac
"#
        ),
    )?;
    std::fs::write(src.join("app.wasm"), b"\0asm\x01\0\0\0sealed")?;

    let workspace = data.join("seal-ws");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace)?;
    let source_img = workspace.join("source.img");
    let output_img = workspace.join("output.img");
    build_ro_ext4_from_dir(&src, &source_img, 16)?;

    // Host TAP, owned by the jailed build uid so the dropped firecracker can open
    // it; assigned the gateway IP and a connectivity listener.
    let _ = tokio::process::Command::new("ip")
        .args(["link", "delete", TAP])
        .status()
        .await;
    ip(&["tuntap", "add", "dev", TAP, "mode", "tap", "user", "100000"]).await;
    ip(&["addr", "add", &format!("{GW}/24"), "dev", TAP]).await;
    ip(&["link", "set", TAP, "up"]).await;

    let listener = tokio::net::TcpListener::bind(format!("{GW}:{PORT}")).await?;
    tokio::spawn(async move {
        while let Ok((s, _)) = listener.accept().await {
            drop(s); // accept + close; we only prove reachability
        }
    });

    let tap_for_seal = TAP.to_string();
    let seal: SealFn = Box::new(move || {
        let tap = tap_for_seal.clone();
        Box::pin(async move {
            let _ = tokio::process::Command::new("ip")
                .args(["link", "delete", &tap])
                .status()
                .await;
        })
    });

    let cfg = BuildVmConfig {
        jailer_bin: release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: data.join("vmlinux.bin"),
        toolchain_rootfs: toolchain,
        source_drive: source_img,
        scratch_size_bytes: 256 * 1024 * 1024,
        output_drive: output_img.clone(),
        output_size_bytes: 64 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: 1,
        mem_size_mib: 512,
        vsock_cid: None,
        timeout: Duration::from_secs(60),
        chroot_base: data.join("bj"),
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
        tap_device: Some(TAP.to_string()),
        guest_mac: Some("AA:FC:00:00:30:02".to_string()),
        guest_ip: Some(GUEST.to_string()),
        gateway_ip: Some(GW.to_string()),
        egress_proxy: Some(format!("http://{GW}:{PORT}")), // non-empty → two-phase
        lang_hint: None,
        fetch_deadline: Duration::from_secs(20),
        seal: Some(seal),
    };

    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!("booting networked build VM (fetch-then-seal) ...");
    let result = BuildVm::run("seal-smoke", &cfg, &data.join("run")).await;

    // Always remove the TAP (idempotent; the seal already deleted it).
    ip(&["link", "delete", TAP]).await;

    let run = result?;
    println!("outcome: {:?} (cpu={:?}us wall={:?})", run.outcome, run.cpu_usec, run.wall);
    if let Some(log) = build_output::read_capped(&output_img, "/build.log", 8 * 1024)? {
        println!("--- build.log ---\n{}", String::from_utf8_lossy(&log).trim_end());
    }
    if run.outcome != BuildOutcome::Completed {
        anyhow::bail!("build VM did not complete: {:?}", run.outcome);
    }

    let read = |name: &str| -> String {
        build_output::read_capped(&output_img, name, 64)
            .ok()
            .flatten()
            .map(|b| String::from_utf8_lossy(&b).trim().to_string())
            .unwrap_or_else(|| "<missing>".to_string())
    };
    let fetch_net = read("/fetch-net");
    let compile_net = read("/compile-net");
    println!("fetch-net={fetch_net}  compile-net={compile_net}");

    assert_eq!(fetch_net, "up", "network must be UP during FETCH");
    assert_eq!(compile_net, "down", "network must be SEALED (down) during COMPILE");
    println!("\nPASS: host-enforced fetch-then-seal — network up during fetch, sealed for compile.");
    Ok(())
}
