//! On-box proof that the Bun build toolchain (`bun.ext4`) ships **real Node.js** and
//! that `bun run build` uses it. This is the OFFLINE companion to the networked
//! `bun_networked_solid_vite_build` guard: it needs no internet / build bridge /
//! egress proxy — only KVM + root (jailer) + the `jkbase-build` cgroup.
//!
//! Why this exists: JS build tooling (Vite/Rollup/Babel) is Node-native. `bun run
//! build` honours a tool's `#!/usr/bin/env node` shebang and delegates to real node
//! when it's on PATH; without node, bun runs the tool on its OWN runtime and hits
//! genuine resolver bugs (e.g. vite-plugin-solid -> `solid-refresh/babel`:
//! "Cannot find module '../dist/babel.cjs' from ''"). So the toolchain must carry a
//! real `node` (build-bun.apko.yaml: `nodejs-24`). This boots the toolchain and runs
//! a `build` script of `node probe.js`; the probe prints the node version and
//! `typeof Bun`. We read it back from `/build.log` and assert it ran under REAL node
//! (`node vNN.. / Bun is undefined`) — under the bun runtime `typeof Bun` is
//! `"object"`, so this fails closed if node ever falls out of the image.
//!
//!   cargo build -p jkbase-orch --example node_toolchain_smoke
//!   sudo env DATA=/abs/short/dir FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/short/dir/toolchains/bun.ext4 \
//!       [KERNEL=/abs/.firecracker/vmlinux-6.12.92.bin] \
//!       ./target/debug/examples/node_toolchain_smoke
//!
//! `TOOLCHAIN`, `KERNEL`, and `DATA` must live on the same filesystem (RO images are
//! hard-linked into the jail), and `DATA` must be a SHALLOW path (jailer SUN_LEN).

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};
use std::path::PathBuf;
use std::time::Duration;

/// Minimal Bun server so launch-command resolution succeeds (start script present).
const SERVER_TS: &str = r#"const port = Number(process.env.PORT) || 3000;
Bun.serve({ port, fetch() { return new Response("ok\n"); } });
"#;

/// `build` runs `node probe.js`. If the toolchain ships real node, `bun run build`
/// runs it under node; `probe.js` prints a marker we assert on in `/build.log`.
const PACKAGE_JSON: &str = r#"{
  "name": "node-probe",
  "module": "server.ts",
  "packageManager": "bun@1.3.14",
  "scripts": { "build": "node probe.js", "start": "bun run server.ts" }
}
"#;

/// Plain CommonJS so it runs identically on node and (would-be) bun. Under REAL node
/// `typeof Bun` is `"undefined"`; under the bun runtime it is `"object"` — so the
/// marker distinguishes which engine `bun run build` delegated to.
const PROBE_JS: &str = r#"console.log("NODEPROBE node " + process.version + " / Bun is " + (typeof Bun));
"#;

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
    if !kernel.exists() {
        anyhow::bail!("kernel not found at {} (set KERNEL=)", kernel.display());
    }

    std::fs::create_dir_all(&data)?;
    let workspace = data.join("ws-nodeprobe");
    let _ = std::fs::remove_dir_all(&workspace);
    let src_dir = workspace.join("src");
    std::fs::create_dir_all(&src_dir)?;
    std::fs::write(src_dir.join("server.ts"), SERVER_TS)?;
    std::fs::write(src_dir.join("package.json"), PACKAGE_JSON)?;
    std::fs::write(src_dir.join("probe.js"), PROBE_JS)?;

    let source_img = workspace.join("nodeprobe.source.img");
    let output_img = workspace.join("nodeprobe.output.img");
    println!("[1/3] baking RO source drive (no mount) ...");
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
        chroot_base: data.join("bj-np"),
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
        export_layered: false,
        build_function: false,
        build_static: false,
        builder_hint: None,
        dockerfile: None,
        fetch_deadline: Duration::from_secs(120),
        seal: None,
    };

    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!("[2/3] booting jailed build VM on the toolchain (timeout {}s) ...", cfg.timeout.as_secs());
    let run = BuildVm::run("np", &cfg, &data.join("run")).await?;
    println!("    outcome: {:?} (cpu={:?}us wall={:?})", run.outcome, run.cpu_usec, run.wall);

    // The build SUBPROCESS (`node probe.js`) writes to the VM console, captured by the
    // orchestrator at {runtime_dir}/{id}.console.log — NOT /out/build.log, which holds
    // only the lifecycle's own `append_log` lines.
    let console = std::fs::read(data.join("run").join("np.console.log"))
        .map(|b| String::from_utf8_lossy(&b).into_owned())
        .unwrap_or_default();
    let marker = console.lines().find(|l| l.contains("NODEPROBE")).map(str::trim);
    println!("    console probe line: {marker:?}");

    if run.outcome != BuildOutcome::Completed {
        anyhow::bail!("build VM did not power off cleanly: {:?}", run.outcome);
    }
    let status = build_output::read_status(&output_img)?;
    if status != Some(0) {
        anyhow::bail!("jkbuild lifecycle exited non-zero: {status:?} (node missing from the toolchain?)");
    }

    println!("[3/3] asserting `bun run build` ran under REAL node ...");
    if !console.contains("NODEPROBE node v") {
        anyhow::bail!("probe marker absent in console — `node probe.js` did not run (no node in the toolchain?)");
    }
    if !console.contains("Bun is undefined") {
        anyhow::bail!(
            "`bun run build` ran the probe under the BUN runtime, not node (`typeof Bun` != undefined) — node not on the build PATH"
        );
    }

    println!("\nPASS: the toolchain ships real node and `bun run build` delegates to it ({}).",
        marker.unwrap_or(""));
    Ok(())
}
