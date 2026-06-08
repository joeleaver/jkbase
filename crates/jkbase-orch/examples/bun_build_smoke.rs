//! On-box validation of the **Bun server build** the `jkbuild` lifecycle drives
//! inside a jailed build VM (WS1 lifecycle + WS2 `bun.ext4` apko image + WS3 Bun
//! buildpack). Formalizes the previously-ad-hoc flat-rung smoke into a committed,
//! reproducible example.
//!
//! A real (no-dep) Bun app is packed into the RO source drive; the build VM boots
//! `bun.ext4` whose `/sbin/init` is `jkbuild-init` (PID1). The lifecycle detects
//! `jkbase/bun` (via `jkbase.lang=bun`), runs `bun install` under Wolfi glibc, and
//! exports a FLAT artifact (`/rootfs.tar.gz` + `/manifest.json`). We read it back
//! from the output drive via debugfs (no mount; threat-model P0-3) and assert the
//! launch contract: `cmd = ["/opt/bun/bin/bun","run","start"]`, `working_dir`
//! `/app`, `env.NODE_ENV = production`.
//!
//! This is the OFFLINE rung (no dependency fetch, so no egress proxy / seal). For
//! the networked `bun install`-through-the-proxy path see `build_seal_smoke`.
//!
//! Needs KVM + root (jailer), so it can't run in CI. Build unprivileged, run via
//! sudo (mirrors `build_pipeline_smoke`):
//!
//!   cargo build -p jkbase-orch --example bun_build_smoke
//!   sudo env DATA=/abs/jkb-bun FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/.firecracker/toolchains/bun.ext4 \
//!       [KERNEL=/abs/.firecracker/vmlinux-6.12.92.bin] \
//!       ./target/debug/examples/bun_build_smoke
//!
//! `TOOLCHAIN` (the `bun.ext4` apko image), `KERNEL`, and `DATA` must live on the
//! same filesystem (RO images are hard-linked into the jail), and `DATA` must be
//! a SHALLOW path (the jailer socket path is bounded by SUN_LEN = 108 bytes).
//! `KERNEL` defaults to `<DATA>/vmlinux-6.12.92.bin`, falling back to
//! `<DATA>/vmlinux.bin`. Expects the parent cgroup `<cgroup_mount>/jkbase-build`
//! provisioned with `+pids +memory +cpu` delegated.

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};
use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

/// Minimal no-dependency Bun server. Reads `PORT` from the env (set by the runtime
/// supervisor), so it satisfies the launch contract without any network fetch.
const SERVER_TS: &str = r#"const port = Number(process.env.PORT) || 3000;
Bun.serve({ port, fetch() { return new Response("ok\n"); } });
console.log("listening on " + port);
"#;

/// `scripts.start` drives the launch-command resolution to
/// `["/opt/bun/bin/bun","run","start"]` (absolute `cmd[0]`); `packageManager`
/// makes host-side `detect_language` agree even without the `jkbase.lang` hint.
const PACKAGE_JSON: &str = r#"{
  "name": "bun-smoke",
  "module": "server.ts",
  "packageManager": "bun@1.1.45",
  "scripts": { "start": "bun run server.ts" }
}
"#;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let toolchain = PathBuf::from(std::env::var("TOOLCHAIN").expect("set TOOLCHAIN (bun.ext4)"));
    let release = fc_dir.join("release-v1.15.1-x86_64");

    // Bun layered work targets the 6.12 guest kernel; the flat rung only needs a
    // bootable kernel, so prefer 6.12 and fall back to the legacy image.
    let kernel = match std::env::var("KERNEL") {
        Ok(k) => PathBuf::from(k),
        Err(_) => {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() { lts } else { data.join("vmlinux.bin") }
        }
    };
    if !kernel.exists() {
        anyhow::bail!("kernel not found at {} (set KERNEL=)", kernel.display());
    }

    std::fs::create_dir_all(&data)?;
    let workspace = data.join("ws");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace)?;

    // Write the inline Bun fixture, then bake it into a RO ext4 source drive
    // (userspace mkfs.ext4 -d, no mount).
    let src_dir = workspace.join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("server.ts"), SERVER_TS)?;
    std::fs::write(src_dir.join("package.json"), PACKAGE_JSON)?;

    let source_img = workspace.join("bun-app.source.img");
    let output_img = workspace.join("bun-app.output.img");
    println!("[1/4] baking RO source drive from inline Bun fixture (no mount) ...");
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
        // Short subdir: the jailer nests the chroot under the (long) firecracker
        // exec basename, so a deep `chroot_base` blows the 108-byte SUN_LEN socket
        // path. Keep `DATA` shallow too.
        chroot_base: data.join("bj"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100_000,
        gid: 100_000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: 512,
        // Headroom above the 1 GiB guest: FC overhead + demand-paged guest RAM
        // must fit, or the build is host-OOM-killed before it can finish.
        cgroup_mem_max_bytes: 1536 * 1024 * 1024,
        cgroup_cpu_max: "200000 100000".to_string(),
        // RLIMIT_FSIZE is process-wide on FC and must cover the largest RW backing
        // file (scratch, 256 MiB) — a smaller cap SIGXFSZ-kills the VM mid-build.
        fsize_limit_bytes: Some(256 * 1024 * 1024),
        console_log_max_bytes: 1024 * 1024,
        seccomp_filter: None,
        netns: None,
        // Offline rung: no TAP / proxy / seal — the in-VM lifecycle skips the
        // fetch-window/seal handshake and builds in a single offline pass.
        tap_device: None,
        guest_mac: None,
        guest_ip: None,
        gateway_ip: None,
        egress_proxy: None,
        lang_hint: Some("bun".to_string()),
        fetch_deadline: Duration::from_secs(120),
        seal: None,
    };

    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!(
        "[2/4] booting jailed Bun build VM on {} (timeout {}s) ...",
        kernel.display(),
        cfg.timeout.as_secs()
    );
    let run = BuildVm::run("bs", &cfg, &data.join("run")).await?;
    let outcome = run.outcome;
    println!("    outcome: {outcome:?} (cpu={:?}us wall={:?})", run.cpu_usec, run.wall);

    if let Some(log) = build_output::read_capped(&output_img, "/build.log", 16 * 1024)? {
        println!("    --- build.log ---\n{}\n    -----------------", String::from_utf8_lossy(&log).trim_end());
    }
    if outcome != BuildOutcome::Completed {
        anyhow::bail!("build VM did not power off cleanly: {outcome:?}");
    }

    println!("[3/4] reading the flat artifact back via debugfs (no mount) ...");
    let status = build_output::read_status(&output_img)?;
    println!("    /status (lifecycle exit code): {status:?}");
    if status != Some(0) {
        anyhow::bail!("jkbuild lifecycle exited non-zero: {status:?}");
    }

    // /rootfs.tar.gz — present, gzip-framed, and contains the app source.
    let rootfs_out = workspace.join("rootfs.tar.gz");
    if !build_output::dump_file(&output_img, "/rootfs.tar.gz", &rootfs_out)? {
        anyhow::bail!("no /rootfs.tar.gz on the output drive");
    }
    let tar_gz = std::fs::read(&rootfs_out)?;
    if tar_gz.len() < 2 || tar_gz[0] != 0x1f || tar_gz[1] != 0x8b {
        anyhow::bail!("/rootfs.tar.gz is not gzip-framed (bad magic)");
    }
    let entries = list_tar_gz(&tar_gz)?;
    println!("    /rootfs.tar.gz: {} bytes, {} entries", tar_gz.len(), entries.len());
    if !entries.iter().any(|e| e.ends_with("server.ts")) {
        anyhow::bail!("exported rootfs is missing server.ts (entries: {entries:?})");
    }

    println!("[4/4] checking the launch manifest ...");
    let mani_out = workspace.join("manifest.json");
    if !build_output::dump_file(&output_img, "/manifest.json", &mani_out)? {
        anyhow::bail!("no /manifest.json on the output drive");
    }
    let mani: serde_json::Value = serde_json::from_slice(&std::fs::read(&mani_out)?)?;
    println!("    manifest: {}", serde_json::to_string(&mani)?);
    let cmd = mani["cmd"].as_array().map(|a| a.as_slice()).unwrap_or(&[]);
    let cmd: Vec<&str> = cmd.iter().filter_map(|v| v.as_str()).collect();
    if cmd != ["/opt/bun/bin/bun", "run", "start"] {
        anyhow::bail!("unexpected launch cmd: {cmd:?} (want absolute /opt/bun/bin/bun run start)");
    }
    if mani["working_dir"] != "/app" {
        anyhow::bail!("unexpected working_dir: {}", mani["working_dir"]);
    }
    if mani["env"]["NODE_ENV"] != "production" {
        anyhow::bail!("missing env NODE_ENV=production: {}", mani["env"]);
    }

    println!("\nPASS: Bun source -> bun.ext4 build VM -> flat rootfs + launch manifest, end-to-end.");
    Ok(())
}

/// List the paths inside a gzipped tarball (for content assertions).
fn list_tar_gz(bytes: &[u8]) -> anyhow::Result<Vec<String>> {
    let mut gz = flate2::read::GzDecoder::new(bytes);
    let mut raw = Vec::new();
    gz.read_to_end(&mut raw)?;
    let mut ar = tar::Archive::new(&raw[..]);
    let mut out = Vec::new();
    for entry in ar.entries()? {
        let entry = entry?;
        out.push(entry.path()?.to_string_lossy().into_owned());
    }
    Ok(out)
}
