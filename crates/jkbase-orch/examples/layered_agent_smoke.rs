//! WS4 wire gauntlet: prove the **real `jkbase-agent`** serves a layered server
//! end-to-end in a guest on the 6.12 kernel, exercising the production code path
//! (NOT a hand-rolled busybox init like `layered_runtime_smoke`). This validates
//! the make-or-break new mechanism: the agent reads a host-written `_layers.json`,
//! mounts the shared base/runtime + per-app erofs layers, and starts the server in
//! its **own** mount namespace via overlay + `pivot_root` (per-server, replacing
//! chroot) — then routes an HTTP request to it.
//!
//! Per VM: vda = agent base rootfs (RO, the musl agent at /sbin/init); vdb =
//! metadata ext4 (_servers/api.json + _routes.json + _layers.json); vdc = shared
//! `base`; vdd = shared `bun-runtime`; vde = per-app layer. `_layers.json` maps
//! server `api` → [vde(app), vdd(runtime), vdc(base)]. The host curls the guest
//! agent on :80, which proxies to the layered bun server → 200.
//!
//! Prereqs: `tools/build-base-layer.sh` has populated `.firecracker/baselayers/`,
//! and the musl agent is built (`cargo build --release -p jkbase-agent --target
//! x86_64-unknown-linux-musl`). Needs root (tap + FC) + /dev/kvm. Run:
//! `cargo build -p jkbase-orch --example layered_agent_smoke` then
//! `sudo ./target/debug/examples/layered_agent_smoke`.

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TAP: &str = "jkagenttap";
// 172.30.x point-to-point (clear of the persistent build bridge jkbuild0 @ 172.31.x).
const HOST_IP: &str = "172.30.0.1";
const GUEST_IP: &str = "172.30.0.2";
const GUEST_MAC: &str = "AA:FC:00:00:30:02";
const AGENT_PORT: u16 = 80;

const SERVER_TS: &str = r#"const port = Number(process.env.PORT) || 3000;
Bun.serve({ port, fetch() { return new Response("ok\n"); } });
console.log("layered server listening on " + port);
"#;
const PACKAGE_JSON: &str =
    r#"{ "name": "layered-agent-smoke", "module": "server.ts", "scripts": { "start": "bun run server.ts" } }"#;

async fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = tokio::process::Command::new(cmd).args(args).output().await?;
    if !out.status.success() {
        anyhow::bail!("{cmd} {args:?}: {}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let repo = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .to_path_buf();
    let fc = repo.join(".firecracker");
    let kernel = fc.join("vmlinux-6.12.92.bin");
    let fc_bin = fc.join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64");
    let store = fc.join("baselayers");
    let agent_bin = repo.join("target/x86_64-unknown-linux-musl/release/jkbase-agent");
    for (label, p) in [("kernel", &kernel), ("firecracker", &fc_bin), ("agent", &agent_bin)] {
        anyhow::ensure!(
            p.exists(),
            "{label} not found at {} (agent: cargo build --release -p jkbase-agent --target x86_64-unknown-linux-musl)",
            p.display()
        );
    }
    anyhow::ensure!(
        store.join("platform.json").exists(),
        "layer store missing — run tools/build-base-layer.sh first"
    );

    let work = std::env::temp_dir().join(format!("layered-agent-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    // --- resolve shared base + bun runtime blobs from the layer store ---
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.join("platform.json"))?)?;
    let base_blob = store.join(manifest["base"]["file"].as_str().unwrap());
    let runtime_blob = store.join(manifest["runtimes"]["bun"]["file"].as_str().unwrap());
    println!("[1/6] layer store: base={} runtime={}", base_blob.display(), runtime_blob.display());

    // --- per-app erofs layer (workspace rooted at /app) ---
    let app_stage = work.join("app-stage");
    std::fs::create_dir_all(app_stage.join("app"))?;
    std::fs::write(app_stage.join("app/server.ts"), SERVER_TS)?;
    std::fs::write(app_stage.join("app/package.json"), PACKAGE_JSON)?;
    let app_blob = work.join("app.erofs");
    run("mkfs.erofs", &["-zlz4hc", "--all-root", "-T", "0", "--mkfs-time",
        app_blob.to_str().unwrap(), app_stage.to_str().unwrap()]).await?;
    println!("[2/6] built app layer {}", app_blob.display());

    // --- agent base rootfs (vda): the musl agent as PID1 + the mount skeleton ---
    let vda_stage = work.join("vda-stage");
    for d in ["sbin", "proc", "sys", "dev", "tmp", "srv/www", "mnt/data"] {
        std::fs::create_dir_all(vda_stage.join(d))?;
    }
    std::fs::copy(&agent_bin, vda_stage.join("sbin/init"))?;
    set_exec(&vda_stage.join("sbin/init"))?;
    let vda_img = work.join("vda.ext4");
    build_ro_ext4_from_dir(&vda_stage, &vda_img, 48)?;
    println!("[3/6] built agent rootfs {}", vda_img.display());

    // --- metadata image (vdb): server manifest + routes + the host-written layer map ---
    let meta_stage = work.join("meta-stage");
    std::fs::create_dir_all(meta_stage.join("_servers"))?;
    let server_manifest = serde_json::json!({
        "port": 3000,
        "cmd": ["/opt/bun/bin/bun", "run", "start"],
        "env": { "NODE_ENV": "production" },
        "working_dir": "/app",
        "health_check": null,
        "volumes": [],
    });
    std::fs::write(
        meta_stage.join("_servers/api.json"),
        serde_json::to_vec_pretty(&server_manifest)?,
    )?;
    let routes = serde_json::json!({ "/": { "service": "server", "name": "api" } });
    std::fs::write(meta_stage.join("_routes.json"), serde_json::to_vec_pretty(&routes)?)?;
    // Device assignment committed below: vdc=base, vdd=runtime, vde=app. The layer
    // order is the overlayfs lowerdir order (app first, base last).
    let layers = serde_json::json!({
        "schema": 1,
        "data_device": null,
        "servers": { "api": { "layers": ["/dev/vde", "/dev/vdd", "/dev/vdc"] } },
    });
    std::fs::write(meta_stage.join("_layers.json"), serde_json::to_vec_pretty(&layers)?)?;
    let meta_img = work.join("metadata.ext4");
    build_ro_ext4_from_dir(&meta_stage, &meta_img, 8)?;
    println!("[4/6] built metadata image {}", meta_img.display());

    // --- point-to-point tap ---
    let _ = run("ip", &["link", "del", TAP]).await;
    run("ip", &["tuntap", "add", "dev", TAP, "mode", "tap"]).await?;
    run("ip", &["addr", "add", &format!("{HOST_IP}/24"), "dev", TAP]).await?;
    run("ip", &["link", "set", TAP, "up"]).await?;

    // --- firecracker --no-api config: vda + metadata + 3 erofs layers + eth0 ---
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off ro ip={GUEST_IP}::{HOST_IP}:255.255.255.0::eth0:off init=/sbin/init"
    );
    let cfg = serde_json::json!({
        "boot-source": { "kernel_image_path": kernel, "boot_args": boot_args },
        "machine-config": { "vcpu_count": 2, "mem_size_mib": 1024 },
        "drives": [
            {"drive_id":"rootfs","path_on_host":vda_img,"is_root_device":true,"is_read_only":true},
            {"drive_id":"metadata","path_on_host":meta_img,"is_root_device":false,"is_read_only":true},
            {"drive_id":"base","path_on_host":base_blob,"is_root_device":false,"is_read_only":true},
            {"drive_id":"runtime","path_on_host":runtime_blob,"is_root_device":false,"is_read_only":true},
            {"drive_id":"app","path_on_host":app_blob,"is_root_device":false,"is_read_only":true},
        ],
        "network-interfaces": [
            {"iface_id":"eth0","guest_mac":GUEST_MAC,"host_dev_name":TAP}
        ],
    });
    let fc_json = work.join("fc.json");
    std::fs::write(&fc_json, serde_json::to_vec_pretty(&cfg)?)?;
    let console_log = work.join("console.log");

    println!("[5/6] booting real agent + layered server on 6.12 ...");
    let log = std::fs::File::create(&console_log)?;
    let mut child = tokio::process::Command::new(&fc_bin)
        .arg("--no-api")
        .arg("--config-file")
        .arg(&fc_json)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;

    // --- poll the agent for HTTP 200 (it proxies "/" → the layered server) ---
    let res = poll_http(GUEST_IP, AGENT_PORT, Duration::from_secs(45)).await;

    // --- cleanup (always) ---
    let _ = child.kill().await;
    let _ = run("ip", &["link", "del", TAP]).await;

    match &res {
        Ok(body) => {
            println!("[6/6] HTTP 200 from the agent-routed layered server: {body:?}");
            let _ = std::fs::remove_dir_all(&work);
            println!("\n✅ real agent serves a layered server on 6.12: _layers.json -> erofs mounts -> per-server overlay+pivot_root -> bun -> agent proxy -> 200.");
            Ok(())
        }
        Err(e) => {
            eprintln!("--- console.log (tail) ---");
            if let Ok(s) = std::fs::read_to_string(&console_log) {
                for line in s.lines().rev().take(60).collect::<Vec<_>>().into_iter().rev() {
                    eprintln!("{line}");
                }
            }
            eprintln!("(artifacts kept at {})", work.display());
            anyhow::bail!("agent did not serve HTTP 200: {e}");
        }
    }
}

fn set_exec(p: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let mut perm = std::fs::metadata(p)?.permissions();
    perm.set_mode(0o755);
    std::fs::set_permissions(p, perm)
}

/// Poll a raw HTTP/1.0 GET until 200 or timeout. Returns the trimmed body.
async fn poll_http(ip: &str, port: u16, timeout: Duration) -> anyhow::Result<String> {
    let deadline = Instant::now() + timeout;
    let addr = format!("{ip}:{port}");
    let mut last = String::new();
    while Instant::now() < deadline {
        match http_get(&addr) {
            Ok((200, body)) => return Ok(body),
            Ok((status, _)) => last = format!("status {status}"),
            Err(e) => last = e.to_string(),
        }
        tokio::time::sleep(Duration::from_millis(500)).await;
    }
    anyhow::bail!("no HTTP 200 within {timeout:?} (last: {last})")
}

fn http_get(addr: &str) -> anyhow::Result<(u16, String)> {
    let mut s = TcpStream::connect_timeout(&addr.parse()?, Duration::from_secs(2))?;
    s.set_read_timeout(Some(Duration::from_secs(2)))?;
    s.write_all(b"GET / HTTP/1.0\r\nHost: jkbase\r\n\r\n")?;
    let mut raw = Vec::new();
    s.read_to_end(&mut raw)?;
    let text = String::from_utf8_lossy(&raw);
    let (head, body) = text.split_once("\r\n\r\n").unwrap_or((&text, ""));
    let status = head
        .lines()
        .next()
        .and_then(|l| l.split_whitespace().nth(1))
        .and_then(|c| c.parse::<u16>().ok())
        .ok_or_else(|| anyhow::anyhow!("no status line"))?;
    Ok((status, body.trim().to_string()))
}
