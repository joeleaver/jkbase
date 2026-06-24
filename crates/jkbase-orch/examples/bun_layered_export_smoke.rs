//! On-box validation of the Bun **layered** export (WS4): the same build VM as
//! `bun_build_smoke`, but with `jkbase.export=layered`, so the in-VM lifecycle
//! emits a content-addressed erofs **app layer** + `/out/layers/index.json`
//! instead of the flat `rootfs.tar.gz`. We read the index + the blob back via
//! debugfs (no mount of the untrusted output drive, P0-3), then mount-check the
//! exported app layer to confirm the workspace is rooted at `/app` (so it composes
//! at the right place under the runtime overlay).
//!
//! Needs KVM + root. Run:
//!   cargo build -p jkbase-orch --example bun_layered_export_smoke
//!   sudo env DATA=/abs/jkb-bunl FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/.firecracker/toolchains/bun.ext4 \
//!       [KERNEL=/abs/.firecracker/vmlinux-6.12.92.bin] \
//!       ./target/debug/examples/bun_layered_export_smoke

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};
use std::path::PathBuf;
use std::time::Duration;

const SERVER_TS: &str = r#"const port = Number(process.env.PORT) || 3000;
Bun.serve({ port, fetch() { return new Response("ok\n"); } });
console.log("listening on " + port);
"#;
const PACKAGE_JSON: &str = r#"{
  "name": "bun-layered-smoke",
  "module": "server.ts",
  "packageManager": "bun@1.3.14",
  "scripts": { "start": "bun run server.ts" }
}
"#;

async fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = tokio::process::Command::new(cmd).args(args).output().await?;
    if !out.status.success() {
        anyhow::bail!("{cmd} {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let toolchain = PathBuf::from(std::env::var("TOOLCHAIN").expect("set TOOLCHAIN (bun.ext4)"));
    let release = fc_dir.join("release-v1.15.1-x86_64");
    let kernel = match std::env::var("KERNEL") {
        Ok(k) => PathBuf::from(k),
        Err(_) => {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        }
    };
    anyhow::ensure!(kernel.exists(), "kernel not found at {} (set KERNEL=)", kernel.display());

    std::fs::create_dir_all(&data)?;
    let workspace = data.join("ws");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace)?;
    let src_dir = workspace.join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("server.ts"), SERVER_TS)?;
    std::fs::write(src_dir.join("package.json"), PACKAGE_JSON)?;

    let source_img = workspace.join("bun-app.source.img");
    let output_img = workspace.join("bun-app.output.img");
    println!("[1/4] baking RO source drive from inline Bun fixture ...");
    build_ro_ext4_from_dir(&src_dir, &source_img, 16)?;

    let cfg = BuildVmConfig {
        jailer_bin: release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: kernel.clone(),
        toolchain_rootfs: toolchain,
        source_drive: source_img.clone(),
        scratch_size_bytes: 256 * 1024 * 1024,
        output_drive: output_img.clone(),
        output_size_bytes: 64 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: 2,
        mem_size_mib: 1024,
        vsock_cid: None,
        timeout: Duration::from_secs(120),
        chroot_base: data.join("bj"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100_000,
        gid: 100_000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: 512,
        cgroup_mem_max_bytes: 1536 * 1024 * 1024,
        cgroup_cpu_max: "200000 100000".to_string(),
        fsize_limit_bytes: Some(256 * 1024 * 1024),
        console_log_max_bytes: 1024 * 1024,
        seccomp_filter: None,
        netns: None,
        tap_device: None,
        guest_mac: None,
        guest_ip: None,
        gateway_ip: None,
        egress_proxy: None,
        lang_hint: Some("bun".to_string()),
        export_layered: true,
        build_function: false,
        build_static: false,
        builder_hint: None,
        dockerfile: None,
        fetch_deadline: Duration::from_secs(120),
        seal: None,
    };
    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!("[2/4] booting jailed Bun build VM (jkbase.export=layered) ...");
    let run_res = BuildVm::run("bls", &cfg, &data.join("run")).await?;
    println!("    outcome: {:?} (wall={:?})", run_res.outcome, run_res.wall);
    if let Some(log) = build_output::read_capped(&output_img, "/build.log", 16 * 1024)? {
        println!("    --- build.log ---\n{}\n    -----------------", String::from_utf8_lossy(&log).trim_end());
    }
    anyhow::ensure!(run_res.outcome == BuildOutcome::Completed, "VM did not power off cleanly: {:?}", run_res.outcome);
    anyhow::ensure!(build_output::read_status(&output_img)? == Some(0), "lifecycle status != 0");

    println!("[3/4] reading /out/layers/index.json via debugfs ...");
    let index_out = workspace.join("index.json");
    anyhow::ensure!(
        build_output::dump_file(&output_img, "/layers/index.json", &index_out)?,
        "no /layers/index.json on the output drive"
    );
    let index: serde_json::Value = serde_json::from_slice(&std::fs::read(&index_out)?)?;
    println!("    index: {}", serde_json::to_string(&index)?);
    let layers = index["layers"].as_array().cloned().unwrap_or_default();
    // jkbuild only emits the per-app layer; the host injects base + runtime by digest.
    anyhow::ensure!(layers.len() == 1, "expected exactly 1 (app) layer, got {}", layers.len());
    let app = &layers[0];
    anyhow::ensure!(app["role"] == "app", "layer role != app: {}", app["role"]);
    anyhow::ensure!(app["media"] == "erofs", "layer media != erofs: {}", app["media"]);
    let digest = app["digest"].as_str().unwrap_or("");
    let file = app["file"].as_str().unwrap_or("");
    anyhow::ensure!(digest.starts_with("sha256:") && file.starts_with("sha256-") && file.ends_with(".erofs"),
        "bad layer digest/file: {digest} / {file}");

    println!("[4/4] extracting + mount-checking the app erofs layer ...");
    let blob = workspace.join("app.erofs");
    anyhow::ensure!(
        build_output::dump_file(&output_img, &format!("/layers/{file}"), &blob)?,
        "app layer blob {file} missing on the output drive"
    );
    // Host-side sha256 must match the claimed digest (the integrity guarantee).
    let got = sha256_file(&blob).await?;
    let want = digest.strip_prefix("sha256:").unwrap_or(digest);
    anyhow::ensure!(got == want, "app layer digest mismatch: claimed {want}, got {got}");
    println!("    blob {} bytes, sha256 verified", std::fs::metadata(&blob)?.len());

    // Mount-check: confirm the app is rooted at /app (so it composes correctly).
    let mnt = workspace.join("mnt");
    std::fs::create_dir_all(&mnt)?;
    run("mount", &["-t", "erofs", "-o", "ro,loop", blob.to_str().unwrap(), mnt.to_str().unwrap()]).await?;
    let server_at_app = mnt.join("app/server.ts").exists();
    let _ = run("umount", &[mnt.to_str().unwrap()]).await;
    anyhow::ensure!(server_at_app, "app layer does not root the workspace at /app");

    println!("\nPASS: Bun layered export — /out/layers/index.json + content-addressed app erofs (rooted at /app), digest-verified.");
    Ok(())
}

async fn sha256_file(path: &std::path::Path) -> anyhow::Result<String> {
    let out = tokio::process::Command::new("sha256sum").arg(path).output().await?;
    anyhow::ensure!(out.status.success(), "sha256sum failed");
    Ok(String::from_utf8_lossy(&out.stdout)
        .split_whitespace()
        .next()
        .unwrap_or("")
        .to_string())
}
