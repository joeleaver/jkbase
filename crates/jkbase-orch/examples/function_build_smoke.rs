//! On-box validation of the **Rust function build**: source → ONE `wasi:http`
//! component, built by `jkbuild::function_build` inside a jailed build VM booting
//! `jkbuild-function.ext4` (apko base + injected pinned Rust toolchain with the
//! `wasm32-wasip2` std at `/opt/rust`).
//!
//! The build VM runs OFFLINE (no proxy/seal): the source is pre-vendored on the
//! host (`FN_SRC` contains `Cargo.toml`, `src/`, `vendor/`, `.cargo/config.toml`),
//! so the in-VM `cargo build --offline --target wasm32-wasip2` needs no network.
//! This isolates the toolchain + builder; the networked fetch-then-seal path
//! mirrors `build_seal_smoke`.
//!
//! We read `/function.wasm` back from the output drive via debugfs (no mount;
//! threat-model P0-3) and assert it is a **component** (preamble layer = 1).
//!
//! Needs KVM + root (jailer). Build unprivileged, then run via sudo:
//!
//!   cargo build -p jkbase-orch --example function_build_smoke
//!   sudo env DATA=/abs/jkb-fn FC_DIR=/abs/.firecracker \
//!       TOOLCHAIN=/abs/.firecracker/toolchains/jkbuild-function.ext4 \
//!       FN_SRC=/abs/jkb-fn/fnsrc \
//!       [KERNEL=/abs/.firecracker/vmlinux-6.12.92.bin] \
//!       ./target/debug/examples/function_build_smoke

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use jkbase_orch::build_output;
use jkbase_orch::build_vm::{BuildOutcome, BuildVm, BuildVmConfig};
use std::path::PathBuf;
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let data = PathBuf::from(std::env::var("DATA").expect("set DATA"));
    let fc_dir = PathBuf::from(std::env::var("FC_DIR").expect("set FC_DIR"));
    let toolchain =
        PathBuf::from(std::env::var("TOOLCHAIN").expect("set TOOLCHAIN (jkbuild-function.ext4)"));
    let fn_src = PathBuf::from(
        std::env::var("FN_SRC").expect("set FN_SRC (a pre-vendored Rust function source dir)"),
    );
    let release = fc_dir.join("release-v1.15.1-x86_64");

    let kernel = match std::env::var("KERNEL") {
        Ok(k) => PathBuf::from(k),
        Err(_) => {
            let lts = data.join("vmlinux-6.12.92.bin");
            if lts.exists() {
                lts
            } else {
                data.join("vmlinux.bin")
            }
        }
    };
    if !kernel.exists() {
        anyhow::bail!("kernel not found at {} (set KERNEL=)", kernel.display());
    }
    if !fn_src.join("Cargo.toml").exists() && !fn_src.join("package.json").exists() {
        anyhow::bail!("FN_SRC {} has neither Cargo.toml nor package.json", fn_src.display());
    }

    std::fs::create_dir_all(&data)?;
    let workspace = data.join("ws");
    let _ = std::fs::remove_dir_all(&workspace);
    std::fs::create_dir_all(&workspace)?;

    let source_img = workspace.join("fn.source.img");
    let output_img = workspace.join("fn.output.img");
    println!("[1/4] baking RO source drive from {} (no mount) ...", fn_src.display());
    // The vendored tree can be tens of MiB; give the source fs generous slack.
    build_ro_ext4_from_dir(&fn_src, &source_img, 64)?;

    let cfg = BuildVmConfig {
        jailer_bin: release.join("jailer-v1.15.1-x86_64"),
        firecracker_bin: release.join("firecracker-v1.15.1-x86_64"),
        kernel_path: kernel.clone(),
        toolchain_rootfs: toolchain,
        source_drive: source_img.clone(),
        // Rust compiles heavier than Bun: give scratch (target/ + incremental) room.
        scratch_size_bytes: 1024 * 1024 * 1024,
        output_drive: output_img.clone(),
        output_size_bytes: 32 * 1024 * 1024,
        cache_drive: None,
        vcpu_count: 4,
        mem_size_mib: 2048,
        vsock_cid: None,
        timeout: Duration::from_secs(360),
        chroot_base: data.join("fj"),
        cgroup_mount: PathBuf::from("/sys/fs/cgroup"),
        uid: 100_000,
        gid: 100_000,
        parent_cgroup: "jkbase-build".to_string(),
        cgroup_pids_max: 1024,
        cgroup_mem_max_bytes: 2560 * 1024 * 1024,
        cgroup_cpu_max: "400000 100000".to_string(),
        fsize_limit_bytes: Some(1024 * 1024 * 1024),
        console_log_max_bytes: 2 * 1024 * 1024,
        seccomp_filter: None,
        netns: None,
        // Offline: source is pre-vendored, so no TAP/proxy/seal.
        tap_device: None,
        guest_mac: None,
        guest_ip: None,
        gateway_ip: None,
        egress_proxy: None,
        // LANG_HINT selects the in-VM function builder (rust | javascript). Default rust.
        lang_hint: Some(std::env::var("LANG_HINT").unwrap_or_else(|_| "rust".to_string())),
        export_layered: false,
        build_function: true,
        build_static: false,
        builder_hint: None,
        dockerfile: None,
        fetch_deadline: Duration::from_secs(360),
        seal: None,
    };

    std::fs::create_dir_all(&cfg.chroot_base)?;
    println!(
        "[2/4] booting jailed function build VM on {} (timeout {}s) ...",
        kernel.display(),
        cfg.timeout.as_secs()
    );
    let run = BuildVm::run("fn", &cfg, &data.join("run")).await?;
    let outcome = run.outcome;
    println!("    outcome: {outcome:?} (cpu={:?}us wall={:?})", run.cpu_usec, run.wall);

    if let Some(log) = build_output::read_capped(&output_img, "/build.log", 32 * 1024)? {
        println!(
            "    --- build.log ---\n{}\n    -----------------",
            String::from_utf8_lossy(&log).trim_end()
        );
    }
    if outcome != BuildOutcome::Completed {
        anyhow::bail!("build VM did not power off cleanly: {outcome:?}");
    }

    println!("[3/4] reading the lifecycle status ...");
    let status = build_output::read_status(&output_img)?;
    println!("    /status (lifecycle exit code): {status:?}");
    if status != Some(0) {
        anyhow::bail!("jkbuild lifecycle exited non-zero: {status:?}");
    }

    println!("[4/4] reading /function.wasm and checking it is a component ...");
    let wasm_out = workspace.join("function.wasm");
    if !build_output::dump_file(&output_img, "/function.wasm", &wasm_out)? {
        anyhow::bail!("no /function.wasm on the output drive");
    }
    let bytes = std::fs::read(&wasm_out)?;
    println!("    /function.wasm: {} bytes", bytes.len());
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        anyhow::bail!("/function.wasm is not a wasm binary (bad magic)");
    }
    // Preamble layer (u16 LE at [6..8]): 0 = core module, 1 = component. The function
    // builder must emit a COMPONENT (the wasi:http ABI), never a core module.
    let layer = u16::from_le_bytes([bytes[6], bytes[7]]);
    if layer != 1 {
        anyhow::bail!("/function.wasm is a core module (layer={layer}), expected a component");
    }

    println!(
        "\nPASS: Rust source -> jkbuild-function.ext4 build VM -> /function.wasm \
         ({} bytes, wasi:http component), end-to-end.",
        bytes.len()
    );
    Ok(())
}
