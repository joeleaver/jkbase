//! WS4 mechanism gauntlet: prove the LAYERED runtime end-to-end **in a guest on
//! the 6.12 kernel** before the agent/vm.rs rewrite. A Bun app is served from a
//! content-addressed erofs layer stack composed guest-side — exactly what the
//! real runtime will do, but driven here straight through Firecracker (no
//! VmConfig changes yet), so the kernel mechanism is validated in isolation.
//!
//! Per VM:  vda = a tiny busybox init rootfs (RO),  vdb = shared Wolfi `base`,
//!          vdc = shared `bun-runtime`,  vdd = the per-app layer (server at /app).
//! The init mounts the three erofs layers RO, overlays them
//! (lowerdir=app:runtime:base, upper=tmpfs), `pivot_root`s into the merged view,
//! and execs `/opt/bun/bin/bun run start`. The host then curls the guest over a
//! point-to-point tap and asserts HTTP 200.
//!
//! Prereq: `tools/build-base-layer.sh` has populated `.firecracker/baselayers/`.
//! Needs root (tap + FC) + /dev/kvm. Run:
//!   cargo build -p jkbase-orch --example layered_runtime_smoke
//!   sudo ./target/debug/examples/layered_runtime_smoke

use jkbase_orch::build_image::build_ro_ext4_from_dir;
use std::io::{Read, Write};
use std::net::TcpStream;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

const TAP: &str = "jklayertap";
const HOST_IP: &str = "172.30.0.1";
const GUEST_IP: &str = "172.30.0.2";
const GUEST_MAC: &str = "AA:FC:00:00:30:02";
const PORT: u16 = 3000;

const SERVER_TS: &str = r#"const port = Number(process.env.PORT) || 3000;
Bun.serve({ port, fetch() { return new Response("ok\n"); } });
console.log("listening on " + port);
"#;
const PACKAGE_JSON: &str = r#"{ "name": "layered-smoke", "module": "server.ts", "scripts": { "start": "bun run server.ts" } }"#;

/// The guest PID1: compose the erofs layer stack and hand off to Bun. This is the
/// shape the real agent's mount_layers + compose_overlay + pivot_root will take.
const INIT_SH: &str = r#"#!/bin/busybox sh
BB=/bin/busybox
$BB mount -t proc proc /proc
$BB mount -t sysfs sysfs /sys
$BB mount -t devtmpfs devtmpfs /dev
echo "[layered-init] mounting erofs layers"
$BB mount -t erofs -o ro /dev/vdb /layers/base
$BB mount -t erofs -o ro /dev/vdc /layers/runtime
$BB mount -t erofs -o ro /dev/vdd /layers/app
$BB mount -t tmpfs tmpfs /ovl
$BB mkdir -p /ovl/upper /ovl/work
echo "[layered-init] composing overlay lower=app:runtime:base"
$BB mount -t overlay overlay -o lowerdir=/layers/app:/layers/runtime:/layers/base,upperdir=/ovl/upper,workdir=/ovl/work /merged
$BB mkdir -p /merged/proc /merged/sys /merged/dev /merged/oldroot
$BB mount --move /proc /merged/proc
$BB mount --move /sys /merged/sys
$BB mount --move /dev /merged/dev
echo "[layered-init] pivot_root into the composed runtime"
cd /merged
$BB pivot_root /merged /merged/oldroot
$BB umount -l /oldroot 2>/dev/null
export PORT=3000
export NODE_ENV=production
export HOME=/root
cd /app
echo "[layered-init] exec bun (cmd[0] from the runtime layer)"
exec /opt/bun/bin/bun run start
"#;

async fn run(cmd: &str, args: &[&str]) -> anyhow::Result<()> {
    let out = tokio::process::Command::new(cmd)
        .args(args)
        .output()
        .await?;
    if !out.status.success() {
        anyhow::bail!(
            "{cmd} {args:?}: {}",
            String::from_utf8_lossy(&out.stderr).trim()
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let base = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join(".firecracker");
    let kernel = base.join("vmlinux-6.12.92.bin");
    let fc_bin = base.join("release-v1.15.1-x86_64/firecracker-v1.15.1-x86_64");
    let store = base.join("baselayers");
    let busybox = PathBuf::from("/usr/bin/busybox");
    for (label, p) in [
        ("kernel", &kernel),
        ("firecracker", &fc_bin),
        ("busybox", &busybox),
    ] {
        anyhow::ensure!(
            p.exists(),
            "{label} not found at {} (busybox: apt-get install busybox-static)",
            p.display()
        );
    }
    anyhow::ensure!(
        store.join("platform.json").exists(),
        "layer store missing — run tools/build-base-layer.sh first"
    );

    let work = std::env::temp_dir().join(format!("layered-smoke-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&work);
    std::fs::create_dir_all(&work)?;

    // --- resolve the shared base + bun runtime blobs from the layer store ---
    let manifest: serde_json::Value =
        serde_json::from_slice(&std::fs::read(store.join("platform.json"))?)?;
    let base_blob = store.join(manifest["base"]["file"].as_str().unwrap());
    let runtime_blob = store.join(manifest["runtimes"]["bun"]["file"].as_str().unwrap());
    println!(
        "[1/5] layer store: base={} runtime={}",
        base_blob.display(),
        runtime_blob.display()
    );

    // --- build the per-app erofs layer (workspace rooted at /app) ---
    let app_stage = work.join("app-stage");
    std::fs::create_dir_all(app_stage.join("app"))?;
    std::fs::write(app_stage.join("app/server.ts"), SERVER_TS)?;
    std::fs::write(app_stage.join("app/package.json"), PACKAGE_JSON)?;
    let app_blob = work.join("app.erofs");
    run(
        "mkfs.erofs",
        &[
            "-zlz4hc",
            "--all-root",
            "-T",
            "0",
            "--mkfs-time",
            app_blob.to_str().unwrap(),
            app_stage.to_str().unwrap(),
        ],
    )
    .await?;
    println!("[2/5] built app layer {}", app_blob.display());

    // --- build the tiny busybox init rootfs (vda) ---
    let vda_stage = work.join("vda-stage");
    for d in [
        "bin",
        "proc",
        "sys",
        "dev",
        "ovl",
        "merged",
        "layers/base",
        "layers/runtime",
        "layers/app",
    ] {
        std::fs::create_dir_all(vda_stage.join(d))?;
    }
    std::fs::copy(&busybox, vda_stage.join("bin/busybox"))?;
    std::fs::write(vda_stage.join("init"), INIT_SH)?;
    set_exec(&vda_stage.join("init"))?;
    set_exec(&vda_stage.join("bin/busybox"))?;
    let vda_img = work.join("vda.ext4");
    build_ro_ext4_from_dir(&vda_stage, &vda_img, 8)?;
    println!("[3/5] built init rootfs {}", vda_img.display());

    // --- point-to-point tap (host 172.30.0.1, guest 172.30.0.2) ---
    let _ = run("ip", &["link", "del", TAP]).await;
    run("ip", &["tuntap", "add", "dev", TAP, "mode", "tap"]).await?;
    run("ip", &["addr", "add", &format!("{HOST_IP}/24"), "dev", TAP]).await?;
    run("ip", &["link", "set", TAP, "up"]).await?;

    // --- firecracker --no-api config: vda + 3 erofs layers + eth0 ---
    let boot_args = format!(
        "console=ttyS0 reboot=k panic=1 pci=off ro ip={GUEST_IP}::{HOST_IP}:255.255.255.0::eth0:off init=/init"
    );
    let cfg = serde_json::json!({
        "boot-source": { "kernel_image_path": kernel, "boot_args": boot_args },
        "machine-config": { "vcpu_count": 1, "mem_size_mib": 512 },
        "drives": [
            {"drive_id":"rootfs","path_on_host":vda_img,"is_root_device":true,"is_read_only":true},
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

    println!("[4/5] booting layered runtime VM on 6.12 ...");
    let log = std::fs::File::create(&console_log)?;
    let mut child = tokio::process::Command::new(&fc_bin)
        .arg("--no-api")
        .arg("--config-file")
        .arg(&fc_json)
        .stdout(log.try_clone()?)
        .stderr(log)
        .spawn()?;

    // --- poll the guest for HTTP 200 ---
    let res = poll_http(GUEST_IP, PORT, Duration::from_secs(40)).await;

    // --- cleanup (always) ---
    let _ = child.kill().await;
    let _ = run("ip", &["link", "del", TAP]).await;

    match &res {
        Ok(body) => {
            println!("[5/5] HTTP 200 from the composed layered runtime: {body:?}");
            let _ = std::fs::remove_dir_all(&work);
            println!(
                "\n✅ layered runtime mechanism validated on 6.12: erofs layers -> overlay -> pivot_root -> bun serves over virtio-net."
            );
            Ok(())
        }
        Err(e) => {
            eprintln!("--- console.log (tail) ---");
            if let Ok(s) = std::fs::read_to_string(&console_log) {
                for line in s
                    .lines()
                    .rev()
                    .take(40)
                    .collect::<Vec<_>>()
                    .into_iter()
                    .rev()
                {
                    eprintln!("{line}");
                }
            }
            eprintln!("(artifacts kept at {})", work.display());
            anyhow::bail!("layered runtime did not serve HTTP 200: {e}");
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
