mod clock;
mod container_supervisor;
mod dmverity;
mod function_egress;
mod function_runtime;
mod log_sink;
mod objectstore_host;
mod static_server;

use anyhow::{Context, Result};
use container_supervisor::ContainerSupervisor;
use function_runtime::{FunctionRequest, FunctionRuntime};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use jkbase_common::layers::RuntimeLayers;
use log_sink::LogSink;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{error, info};

fn mount_filesystems() {
    use std::ffi::CString;
    use std::ptr;

    let mounts = [
        ("/proc", "proc", "proc"),
        ("/sys", "sysfs", "sysfs"),
        ("/dev", "devtmpfs", "devtmpfs"),
        ("/tmp", "tmpfs", "tmpfs"),
        // chrony's writable runtime dir (driftfile + command socket) lives here.
        ("/run", "tmpfs", "tmpfs"),
    ];

    for (target, fstype, source) in &mounts {
        let _ = std::fs::create_dir_all(target);
        let src = CString::new(*source).unwrap();
        let tgt = CString::new(*target).unwrap();
        let fst = CString::new(*fstype).unwrap();
        unsafe {
            libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, ptr::null());
        }
    }
}

fn seed_entropy() {
    use std::io::Write;
    let mut seed = [0u8; 512];
    for chunk in seed.chunks_mut(8) {
        let tsc: u64;
        unsafe {
            std::arch::x86_64::_mm_lfence();
            tsc = std::arch::x86_64::_rdtsc();
        }
        let bytes = tsc.to_ne_bytes();
        chunk.copy_from_slice(&bytes[..chunk.len()]);
    }

    if let Ok(mut f) = std::fs::OpenOptions::new().write(true).open("/dev/urandom") {
        let _ = f.write_all(&seed);
    }

    if let Ok(f) = std::fs::OpenOptions::new().write(true).open("/dev/random") {
        use std::os::unix::io::AsRawFd;
        #[repr(C)]
        struct RandPoolInfo {
            entropy_count: i32,
            buf_size: i32,
            buf: [u8; 512],
        }
        let mut info = RandPoolInfo {
            entropy_count: 512 * 8,
            buf_size: 512,
            buf: seed,
        };
        unsafe {
            libc::ioctl(f.as_raw_fd(), 0x40085203, &mut info as *mut _);
        }
    }
}

fn mount_content_drive(target: &str) {
    use std::ffi::CString;
    use std::ptr;

    let device = "/dev/vdb";
    if !std::path::Path::new(device).exists() {
        return;
    }

    let _ = std::fs::create_dir_all(target);
    let src = CString::new(device).unwrap();
    let tgt = CString::new(target).unwrap();
    let fst = CString::new("ext4").unwrap();

    let flags = libc::MS_RDONLY;
    let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), flags, ptr::null()) };
    if ret != 0 {
        eprintln!(
            "failed to mount {device} at {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn mount_data_disk(device: Option<&str>) {
    use std::ffi::CString;
    use std::ptr;

    // The host writes the data-disk device into _layers.json. Fall back to the
    // legacy fixed slot for pre-layered content images, where the data disk was
    // attached right after the content drive (/dev/vdc). With no layers attached,
    // the layered layout also lands the data disk at /dev/vdc, so this is safe.
    let device = device.unwrap_or("/dev/vdc");
    let target = "/mnt/data";

    if !std::path::Path::new(device).exists() {
        return;
    }

    let _ = std::fs::create_dir_all(target);
    let src = CString::new(device).unwrap();
    let tgt = CString::new(target).unwrap();
    let fst = CString::new("ext4").unwrap();

    let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), 0, ptr::null()) };
    if ret == 0 {
        let _ = std::fs::create_dir_all("/mnt/data/volumes");
    } else {
        eprintln!(
            "failed to mount {device} at {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

/// Read the host-written `_layers.json` from the metadata image, if present.
/// Absent ⇒ a legacy flat content image (chroot servers; no erofs layers).
fn load_runtime_layers(serve_dir: &Path) -> Option<RuntimeLayers> {
    let path = serve_dir.join(RuntimeLayers::FILE);
    let content = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<RuntimeLayers>(&content) {
        Ok(rl) => Some(rl),
        Err(e) => {
            eprintln!("failed to parse {}: {e}", path.display());
            None
        }
    }
}

/// Read the host-written `_platform.json` (the host-asserted egress facts) from the
/// metadata image. Absent/malformed ⇒ fail-closed defaults (no OWN-storage host, empty
/// deny-set): stricter, never wider — the agent then leans on the netfilter fence for
/// Zone 2 and treats no host as OWN-storage.
fn load_platform_egress(serve_dir: &Path) -> jkbase_common::config::PlatformEgress {
    let path = serve_dir.join(jkbase_common::config::PlatformEgress::FILE);
    match std::fs::read(&path) {
        Ok(bytes) => serde_json::from_slice(&bytes).unwrap_or_else(|e| {
            eprintln!(
                "failed to parse {}: {e}; using fail-closed egress defaults",
                path.display()
            );
            Default::default()
        }),
        Err(_) => Default::default(),
    }
}

/// Read the host-written `_db_reach.json` reach-plane facts ([R3]/[RB1]) from the metadata
/// image. Absent/malformed ⇒ default (all-empty), so the splice/backup endpoints stay
/// unreachable and the admin token stays unset — fail-closed, never open.
fn load_db_reach_facts(serve_dir: &Path) -> jkbase_common::config::DbReachFacts {
    let path = serve_dir.join(jkbase_common::config::DbReachFacts::FILE);
    std::fs::read(&path)
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// dm-verity mapper name for a layer block device (e.g. `/dev/vdc` → `jkverity-vdc`):
/// stable, unique per device, and within `dmverity::activate`'s accepted name charset.
fn verity_name(device: &str) -> String {
    let base = Path::new(device)
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("dev");
    format!("jkverity-{base}")
}

/// Mount an erofs filesystem read-only from `source` (a raw block device or an
/// activated `/dev/mapper` verity node) at `target`.
fn mount_erofs_ro(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;
    use std::ptr;
    let src = CString::new(source.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("nul byte in source path"))?;
    let tgt = CString::new(target.as_os_str().as_bytes())
        .map_err(|_| std::io::Error::other("nul byte in target path"))?;
    let fst = CString::new("erofs").unwrap();
    let ret = unsafe {
        libc::mount(
            src.as_ptr(),
            tgt.as_ptr(),
            fst.as_ptr(),
            libc::MS_RDONLY,
            ptr::null(),
        )
    };
    if ret != 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

/// Mount each distinct erofs layer block device read-only under /tmp/layers, and
/// return (`server name` → its ordered lowerdir mountpoints, the managed DB's ordered
/// lowerdir mountpoints if declared). App first, base last. A server (or the DB) whose
/// layers don't all mount is omitted (it won't be started layered).
fn mount_layers(rl: &RuntimeLayers) -> (HashMap<String, Vec<PathBuf>>, Option<Vec<PathBuf>>) {
    let base = Path::new("/tmp/layers");
    let _ = std::fs::create_dir_all(base);

    let mountpoint_for = |device: &str| -> PathBuf {
        let name = Path::new(device)
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("dev");
        base.join(name)
    };

    // One clear diagnostic if integrity-enforced layers are declared but this guest
    // can't activate dm-verity (no device-mapper / no veritysetup) — those layers then
    // fail closed per-device below; this just names the root cause once up front.
    if !rl.verity.is_empty() && !dmverity::available() {
        eprintln!(
            "dm-verity required by {} shared layer(s) but device-mapper/veritysetup is \
             unavailable in this guest; verified layers will fail closed (their servers \
             will not start layered)",
            rl.verity.len()
        );
    }

    // Mount each distinct device exactly once. A device listed in `rl.verity` is an
    // integrity-enforced shared layer (the base / per-language runtime, whose poisoning
    // would hit every tenant): activate a dm-verity mapping pinned to its host-computed
    // root hash and mount erofs from the verified `/dev/mapper` node — a tampered block
    // then returns EIO. This is FAIL-CLOSED: if verity activation or the verified mount
    // fails we skip the layer (its server simply won't start layered), never falling
    // through to an unverified direct mount. A device ABSENT from `rl.verity` (the
    // per-tenant app layer — self-affecting + host-sha256-verified at attach — and any
    // pre-verity image) is mounted erofs directly.
    let mut mounted: HashMap<String, PathBuf> = HashMap::new();
    // Every distinct device referenced by any tenant server OR the managed DB overlay.
    let mut layer_lists: Vec<&Vec<String>> = rl.servers.values().map(|s| &s.layers).collect();
    if let Some(db) = &rl.database {
        layer_lists.push(&db.layers);
    }
    for layers in layer_lists {
        for device in layers {
            if mounted.contains_key(device) {
                continue;
            }
            if !Path::new(device).exists() {
                eprintln!("layer device {device} not present; skipping");
                continue;
            }
            let mp = mountpoint_for(device);
            let _ = std::fs::create_dir_all(&mp);

            if let Some(params) = rl.verity.get(device) {
                let name = verity_name(device);
                let dev = match dmverity::activate(&name, Path::new(device), params) {
                    Ok(d) => d,
                    Err(e) => {
                        eprintln!("dm-verity activation failed for {device}: {e}; layer skipped");
                        continue;
                    }
                };
                match mount_erofs_ro(dev.path(), &mp) {
                    Ok(()) => {
                        // The erofs mount now pins the mapping; disarm teardown-on-drop
                        // so dropping the handle here can't tear down the live mount.
                        dev.leak();
                        mounted.insert(device.clone(), mp);
                    }
                    Err(e) => {
                        // Mount failed: `dev` is still armed, so dropping it here tears
                        // the verity mapping down — no leaked dm device.
                        eprintln!(
                            "failed to mount verified erofs {device} at {}: {e}",
                            mp.display()
                        );
                    }
                }
            } else if let Err(e) = mount_erofs_ro(Path::new(device), &mp) {
                eprintln!("failed to mount erofs {device} at {}: {e}", mp.display());
            } else {
                mounted.insert(device.clone(), mp);
            }
        }
    }

    // Resolve each server's ordered devices to mountpoints.
    let mut map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    for (name, server) in &rl.servers {
        let mut dirs = Vec::with_capacity(server.layers.len());
        let mut ok = true;
        for device in &server.layers {
            match mounted.get(device) {
                Some(mp) => dirs.push(mp.clone()),
                None => {
                    ok = false;
                    break;
                }
            }
        }
        if ok && !dirs.is_empty() {
            map.insert(name.clone(), dirs);
        } else {
            eprintln!("server '{name}' has unmounted layers; will not start layered");
        }
    }

    // Resolve the managed DB overlay (lowerdir=rhypedb:base) to mountpoints, if declared.
    let database = rl.database.as_ref().and_then(|db| {
        let mut dirs = Vec::with_capacity(db.layers.len());
        for device in &db.layers {
            match mounted.get(device) {
                Some(mp) => dirs.push(mp.clone()),
                None => {
                    eprintln!("managed DB has an unmounted layer ({device}); will not start");
                    return None;
                }
            }
        }
        (!dirs.is_empty()).then_some(dirs)
    });

    (map, database)
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

struct AgentState {
    serve_dir: PathBuf,
    functions_dir: PathBuf,
    functions: FunctionRuntime,
    containers: Arc<ContainerSupervisor>,
    /// The one process-wide log sink (server output + function egress events),
    /// shared by every producer so the host shipper sees a single `(boot_id, seq)`
    /// cursor space. Read directly by the `/_jkbase/logs` endpoint.
    log_sink: Arc<LogSink>,
    route_config: Vec<RouteEntry>,
    sites: Vec<SiteEntry>,
    /// Host→agent managed-DB reach-plane splice secret ([R3]), read from the host-authored
    /// `_db_reach.json`. `Some` only for a project with a managed DB; the `/_jkbase/db`
    /// handler verifies it before splicing (a `None`/mismatch fails closed).
    db_splice_secret: Option<String>,
    /// The per-deploy rhypedb admin bearer ([RB1]), read from the same host-only
    /// `_db_reach.json`. Used ONLY by the `/_jkbase/db-backup` pull handler to authorize the
    /// loopback `/admin/backup/stream` call — never served, never handed to a tenant process.
    db_admin_token: Option<String>,
}

/// A backend kind a tenant route can target. Resolved at the agent's deserialization
/// boundary ONLY (from `_routes.json` in this VM's host-built metadata image) — the proxy
/// stays unaware of function-vs-server (P0-INGRESS-HOST-TRUST). An unknown kind is dropped
/// (fail-closed) at load.
#[derive(Clone, Copy, PartialEq, Debug)]
enum RouteKind {
    Server,
    Function,
}

struct RouteEntry {
    prefix: String,
    /// Target backend name (server or function) within this project.
    name: String,
    kind: RouteKind,
}

struct SiteEntry {
    name: String,
    root: PathBuf,
    prefix: String,
    spa: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // `jkbase-agent --precompile <in.wasm> <out.cwasm>`: AOT-compile a function with the
    // runtime's exact engine config so the agent deserializes it at boot instead of
    // recompiling the big JS engine. Invoked by the host deploy pipeline (it ships this
    // same binary), so the precompiler and loader configs can never drift.
    let args: Vec<String> = std::env::args().collect();
    if args.get(1).map(String::as_str) == Some("--precompile") {
        let (Some(input), Some(output)) = (args.get(2), args.get(3)) else {
            eprintln!("usage: jkbase-agent --precompile <in.wasm> <out.cwasm>");
            std::process::exit(2);
        };
        function_runtime::precompile(Path::new(input), Path::new(output))?;
        return Ok(());
    }

    if is_pid1() {
        mount_filesystems();
        seed_entropy();
    }

    tracing_subscriber::fmt::init();

    // Discipline the guest wall clock against the host's KVM PTP device via chrony
    // (refclock PHC /dev/ptp0): it corrects the free-running-tsc frequency error and
    // any offset with no network. As PID 1 we own supervising chronyd. The
    // hibernate/resume jump is corrected instantly on demand via POST
    // /_jkbase/resync-clock (chronyc makestep), fired by the host after it resumes a
    // restored snapshot. See clock.rs.
    if is_pid1() {
        clock::start_chrony();
    }

    let serve_dir =
        PathBuf::from(std::env::var("JKBASE_SERVE_DIR").unwrap_or_else(|_| "/srv/www".to_string()));
    let functions_dir = PathBuf::from(
        std::env::var("JKBASE_FUNCTIONS_DIR")
            .unwrap_or_else(|_| serve_dir.join("_functions").to_string_lossy().to_string()),
    );
    let servers_dir = serve_dir.join("_servers");

    let mut layer_map: HashMap<String, Vec<PathBuf>> = HashMap::new();
    let mut db_lowerdirs: Option<Vec<PathBuf>> = None;
    if is_pid1() {
        mount_content_drive(serve_dir.to_str().unwrap_or("/srv/www"));
        // The metadata image carries _layers.json describing this boot's device
        // assignment: the data-disk device and each server's erofs overlay stack.
        match load_runtime_layers(&serve_dir) {
            Some(rl) => {
                // Layered image: mount the data disk only if the host mapped one
                // (the fixed /dev/vdc slot is now a layer, not a data disk), then
                // compose the erofs layer stack.
                if let Some(dev) = rl.data_device.as_deref() {
                    mount_data_disk(Some(dev));
                }
                // Fail-closed on a newer-than-known contract: an image whose schema
                // exceeds what this agent understands may carry integrity semantics
                // (e.g. a verity map) we cannot honour, so refuse the layered mounts
                // rather than silently mount them unverified. The data disk above is
                // schema-independent and still mounts.
                if rl.schema > RuntimeLayers::SCHEMA {
                    eprintln!(
                        "_layers.json schema {} is newer than this agent supports ({}); \
                         refusing layered mounts (fail-closed)",
                        rl.schema,
                        RuntimeLayers::SCHEMA
                    );
                } else {
                    let (lm, db) = mount_layers(&rl);
                    layer_map = lm;
                    db_lowerdirs = db;
                }
            }
            None => {
                // Legacy flat content image: data disk at the fixed /dev/vdc slot.
                mount_data_disk(None);
            }
        }
    }

    // The single shared log sink: one `seq` source + one `boot_id` for the whole
    // agent process, constructed here and handed to every log producer. Both the
    // server supervisor and (in the egress-observe path) the function runtime push
    // into it, so the host shipper dedups on one cursor space (P0-OBS-UNIFIED-SINK).
    let log_sink = Arc::new(LogSink::new());

    // Host-asserted platform egress facts (`_platform.json`): the OWN object-store host +
    // the platform's own public-IP deny-set. Read once at boot; the agent's egress gate
    // classifies against these. Absent/malformed ⇒ fail-closed defaults (no OWN host, empty
    // deny-set → rely on the netfilter fence for Zone 2; stricter, never wider).
    let platform_egress = load_platform_egress(&serve_dir);
    let egress_ctx = function_egress::EgressContext::new(&platform_egress, log_sink.clone())
        .context("build function egress context")?;

    let mut functions = FunctionRuntime::new(egress_ctx);
    if let Err(e) = functions.load_all_from_dir(&functions_dir) {
        error!(error = %e, "failed to load functions");
    }

    let func_names = functions.list_functions();
    if !func_names.is_empty() {
        info!(functions = ?func_names, "loaded WASM functions");
    }

    let containers = Arc::new(ContainerSupervisor::new(
        servers_dir,
        layer_map,
        log_sink.clone(),
    ));
    if let Err(e) = containers.start_all().await {
        error!(error = %e, "failed to start server containers");
    }

    // Managed database (RhypeDB): a dedicated, loopback-only supervised server composed
    // from the rhypedb runtime layer (overlay rhypedb:base) — NOT a tenant `_servers`
    // entry and never routed, reachable only at 127.0.0.1:4200 by the project's own app.
    // Schema (+ optional rules) are host-baked into `_database/` in the metadata image;
    // the agent seeds them into the DB's meta volume before the server starts.
    // Host-only reach-plane facts (splice secret + rhypedb admin token), loaded once from the
    // metadata image before the DB starts so the token can be injected into the DB's env.
    let db_reach = load_db_reach_facts(&serve_dir);
    let db_splice_secret =
        (!db_reach.splice_secret.is_empty()).then(|| db_reach.splice_secret.clone());
    let db_admin_token = (!db_reach.admin_token.is_empty()).then(|| db_reach.admin_token.clone());

    // P2 §7.6 — the app→DB in-guest leg. A dedicated project's app VM has NO co-located rhypedb
    // (`db_lowerdirs.is_none()`); its DB runs in a sibling DB VM. Start the in-guest loopback proxy
    // so tenant code reaches its DB on the SAME `127.0.0.1:4200/4201` as co-located — byte-for-byte
    // unchanged. Each accepted loopback connection is spliced to the host DB gateway on the bridge
    // gateway IP (`172.16.0.1`), which source-IP-authenticates and forwards to the DB VM's agent.
    // The `dedicated` flag is set ONLY on a dedicated APP image; a co-located app (which co-hosts
    // rhypedb on those ports) never sets it, so the two can't collide. Capture BEFORE the DB-start
    // block below moves `db_lowerdirs`.
    //
    // Corrupt-image guard ([R4]): a dedicated app image must NEVER also carry the rhypedb overlay —
    // that could only be a mis-built image, and silently co-locating a SECOND rhypedb (two DB
    // identities) is worse than failing closed. If we ever see `dedicated && db_lowerdirs.is_some()`,
    // shout and DROP the overlay so the co-located DB is not started and the leg (to the real
    // sibling DB VM) is used instead.
    if db_reach.dedicated && db_lowerdirs.is_some() {
        error!(
            "CORRUPT IMAGE: `_db_reach.json` marks this a dedicated app VM, but the metadata image \
             ALSO carries the rhypedb overlay — refusing to co-locate a second DB; using the app→DB \
             leg to the sibling DB VM instead"
        );
        db_lowerdirs = None;
    }
    let start_db_leg = db_reach.dedicated && db_lowerdirs.is_none();

    if let Some(lowerdirs) = db_lowerdirs {
        let schema_path = serve_dir.join("_database/schema.rhype");
        match std::fs::read(&schema_path) {
            Ok(schema) => {
                let rules = std::fs::read(serve_dir.join("_database/rules.rhype")).ok();
                if let Err(e) = containers
                    .start_database(
                        db_admin_token.as_deref(),
                        &schema,
                        rules.as_deref(),
                        lowerdirs,
                    )
                    .await
                {
                    error!(error = %e, "failed to start managed database");
                }
            }
            Err(e) => error!(
                error = %e,
                path = %schema_path.display(),
                "managed DB declared but schema missing from metadata image"
            ),
        }
    }

    // P2 §7.6 — start the app→DB loopback proxy on a dedicated app VM (see `start_db_leg` above).
    if start_db_leg {
        info!(
            "dedicated tier: starting in-guest app→DB loopback proxy \
             (127.0.0.1:{RHYPEDB_HTTP_PORT}/{RHYPEDB_TCP_PORT} → host DB gateway {})",
            jkbase_common::config::DB_GATEWAY_IP
        );
        // HTTP plane (`POST /query`, …) and the native TCP wire (`@rhypedb/client`, subscriptions)
        // each get their own loopback listener → its matching host-gateway port; both share one
        // in-VM concurrency ceiling.
        let leg_permits = std::sync::Arc::new(tokio::sync::Semaphore::new(DB_LEG_MAX_CONNS));
        tokio::spawn(db_leg_loopback_proxy(
            RHYPEDB_HTTP_PORT,
            jkbase_common::config::DB_GATEWAY_HTTP_PORT,
            leg_permits.clone(),
        ));
        tokio::spawn(db_leg_loopback_proxy(
            RHYPEDB_TCP_PORT,
            jkbase_common::config::DB_GATEWAY_WIRE_PORT,
            leg_permits,
        ));
    }

    let route_config = load_route_config(&serve_dir);
    let sites = load_sites_config(&serve_dir);

    if !sites.is_empty() {
        for site in &sites {
            info!(
                site = %site.name,
                prefix = %site.prefix,
                root = %site.root.display(),
                spa = site.spa,
                "loaded site"
            );
        }
    }

    if containers.is_supervising().await {
        let containers_for_health = containers.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(std::time::Duration::from_secs(5)).await;
                containers_for_health.run_health_checks().await;
            }
        });
    }

    let port: u16 = std::env::var("JKBASE_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()?;

    let state = Arc::new(AgentState {
        serve_dir,
        functions_dir,
        functions,
        containers,
        log_sink,
        route_config,
        sites,
        db_splice_secret,
        db_admin_token,
    });

    info!("jkbase-agent starting (pid {})", std::process::id());
    info!(port, "listening");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _peer) = listener.accept().await?;
        // Which interface accepted this connection: the host reaches the agent over the
        // VM's eth0 (dest = guest_ip), the in-VM tenant app over loopback. Used to fence
        // `/_jkbase/*` control endpoints off guest loopback ([R3]). Unknown ⇒ not-loopback
        // (allow) so a local_addr glitch can't break host health checks — the /_jkbase/db
        // splice secret is the real gate regardless.
        let on_loopback = stream
            .local_addr()
            .map(|a| a.ip().is_loopback())
            .unwrap_or(false);
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle_request(state.clone(), req, on_loopback));
            // with_upgrades(): required to proxy WebSockets through to the container.
            if let Err(e) = http1::Builder::new()
                .serve_connection(io, svc)
                .with_upgrades()
                .await
            {
                error!(error = %e, "connection error");
            }
        });
    }
}

fn load_sites_config(serve_dir: &Path) -> Vec<SiteEntry> {
    let sites_path = serve_dir.join("_sites.json");
    if !sites_path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&sites_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let sites: Vec<jkbase_common::config::ResolvedSite> = match serde_json::from_str(&content) {
        Ok(s) => s,
        Err(_) => return Vec::new(),
    };

    // Sites are already sorted by prefix length (longest first) from the CLI
    sites
        .into_iter()
        .map(|s| {
            let root = serve_dir.join(format!("_site_{}", s.name));
            SiteEntry {
                name: s.name,
                root,
                prefix: s.prefix,
                spa: s.spa,
            }
        })
        .filter(|s| s.root.exists())
        .collect()
}

fn load_route_config(serve_dir: &Path) -> Vec<RouteEntry> {
    let routes_path = serve_dir.join("_routes.json");
    if !routes_path.exists() {
        return Vec::new();
    }

    let content = match std::fs::read_to_string(&routes_path) {
        Ok(c) => c,
        Err(_) => return Vec::new(),
    };

    let routes: std::collections::HashMap<String, jkbase_common::config::RouteTarget> =
        match serde_json::from_str(&content) {
            Ok(r) => r,
            Err(_) => return Vec::new(),
        };

    routes
        .iter()
        .filter_map(|(prefix, target)| {
            // Typed backend kind; an unknown service is dropped (forward-compat + fail-closed)
            // rather than silently treated as a server.
            let kind = match target.service.as_str() {
                "server" => RouteKind::Server,
                "function" => RouteKind::Function,
                _ => return None,
            };
            Some(RouteEntry {
                prefix: prefix.clone(),
                name: target.name.clone(),
                kind,
            })
        })
        .collect()
}

async fn handle_request(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
    on_loopback: bool,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // [R3] Control endpoints are for the HOST (reached over the VM's eth0), never the
    // in-VM tenant app. Drop any `/_jkbase/*` that arrived on guest loopback — defense in
    // depth atop each endpoint's own auth (the `/_jkbase/db` splice secret). 404 (not 403)
    // so a probing tenant can't even confirm the endpoint exists.
    if on_loopback && path.starts_with("/_jkbase/") {
        return Ok(not_found_response());
    }

    if path == "/_jkbase/health" {
        return Ok(health_response(&state).await);
    }

    if path == "/_jkbase/db" {
        return Ok(handle_db_splice(state, req).await);
    }

    if path == "/_jkbase/db/backup" {
        return Ok(handle_db_backup(state, req).await);
    }

    if path == "/_jkbase/db/restore" {
        return Ok(handle_db_restore(state, req).await);
    }

    if path == "/_jkbase/db/query" {
        return Ok(handle_db_query(state, req, DbHttpOp::Query).await);
    }

    if path == "/_jkbase/db/schema" {
        return Ok(handle_db_query(state, req, DbHttpOp::Schema).await);
    }

    if path == "/_jkbase/db/status" {
        return Ok(handle_db_query(state, req, DbHttpOp::Status).await);
    }

    if path == "/_jkbase/sync" {
        unsafe { libc::sync() };
        return Ok(Response::builder()
            .status(StatusCode::OK)
            .body(Full::new(Bytes::from("{\"synced\":true}")))
            .unwrap());
    }

    if path == "/_jkbase/resync-clock" {
        return Ok(resync_clock_response(req).await);
    }

    if path == "/_jkbase/logs" || path.starts_with("/_jkbase/logs?") {
        return Ok(logs_response(&state, &req).await);
    }

    // Walk the tenant route table, dispatching by backend kind. A FUNCTION route is
    // request/response only: an upgrade to it gets 426 (before the body is buffered) and a
    // declared-but-missing function 404s WITHOUT falling through to static — so a misspelled
    // function name can't accidentally serve the static site or probe the metadata image.
    // A SERVER route that matches but has no running backend falls through (unchanged).
    for route in &state.route_config {
        let prefix = route.prefix.trim_end_matches('*');
        if !path.starts_with(prefix) {
            continue;
        }
        match route.kind {
            RouteKind::Server => {
                if let Some(port) = state.containers.get_server_for_route(&route.name).await {
                    return Ok(proxy_to_server(port, req).await);
                }
            }
            RouteKind::Function => {
                if jkbase_wsproxy::is_upgrade_request(req.headers()) {
                    return Ok(upgrade_required_response());
                }
                if state.functions.has_function(&route.name) {
                    // Own the name so nothing borrows `state.route_config` across the move.
                    let name = route.name.clone();
                    info!(function = %name, path = %path, "routing to function (route)");
                    return Ok(invoke_function(state.clone(), &name, req).await);
                }
                return Ok(not_found_response());
            }
        }
    }

    // Legacy implicit function route: `/functions/{name}`. Same request/response rules —
    // 426 on upgrade, 404 (no fallthrough) on a missing function.
    if let Some(func_name) = extract_function_name(&path) {
        if jkbase_wsproxy::is_upgrade_request(req.headers()) {
            return Ok(upgrade_required_response());
        }
        if state.functions.has_function(&func_name) {
            info!(function = %func_name, path = %path, "routing to function");
            return Ok(invoke_function(state, &func_name, req).await);
        }
        return Ok(not_found_response());
    }

    // Host-bound site: the proxy sets X-Jkbase-Site (stripped from inbound, so
    // trusted) when the request's hostname maps to a specific site. Serve that
    // site's whole tree.
    if let Some(site_name) = req
        .headers()
        .get("x-jkbase-site")
        .and_then(|v| v.to_str().ok())
        && let Some(site) = state.sites.iter().find(|s| s.name == site_name)
    {
        return static_server::handle_static_with_path(
            &site.root,
            &path,
            site.spa,
            &static_server::ReqConds::from_headers(req.headers()),
        )
        .await;
    }

    // Multi-site routing: find the best matching site by prefix
    if !state.sites.is_empty() {
        for site in &state.sites {
            let prefix = site.prefix.trim_end_matches('/');
            if prefix.is_empty() || path.starts_with(prefix) {
                let sub_path = if prefix.is_empty() {
                    path.to_string()
                } else {
                    path.strip_prefix(prefix).unwrap_or(&path).to_string()
                };
                return static_server::handle_static_with_path(
                    &site.root,
                    &sub_path,
                    site.spa,
                    &static_server::ReqConds::from_headers(req.headers()),
                )
                .await;
            }
        }
    }

    // Fall through to default static file serving. handle_static serves the image
    // ROOT, which holds the host-internal `_`-prefixed control files
    // (`_servers/*.json` carries the app env, plus `_routes`/`_sites`/`_layers`/
    // `_layerpaths`/`_functions`) — so it refuses any request that resolves onto a
    // `_`-prefixed top-level entry, keeping tenant config off the public surface.
    // (Site roots `_site_<name>/` are served via the site paths above, where
    // `_`-prefixed framework dirs like `_next/` remain legitimate.)
    static_server::handle_static(&state.serve_dir, req).await
}

async fn health_response(state: &AgentState) -> Response<Full<Bytes>> {
    let functions = state.functions.list_functions();
    let servers = state.containers.status().await;
    let body = serde_json::json!({
        "status": "ok",
        "pid": std::process::id(),
        "serve_dir": state.serve_dir.display().to_string(),
        "functions_loaded": functions,
        "functions_dir_exists": state.functions_dir.exists(),
        "functions_dir": state.functions_dir.display().to_string(),
        "servers": servers,
        // Echoed so the host's VM re-adoption path can detect agent-protocol skew at adopt
        // time and force-recycle instead of re-adopting an incompatible old agent (§9).
        "agent_protocol": jkbase_common::AGENT_PROTOCOL_VERSION,
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .header(
            jkbase_common::AGENT_PROTOCOL_HEADER,
            jkbase_common::AGENT_PROTOCOL_VERSION.to_string(),
        )
        .body(Full::new(Bytes::from(
            serde_json::to_vec_pretty(&body).unwrap(),
        )))
        .unwrap()
}

/// Re-discipline the guest wall clock on demand by stepping CLOCK_REALTIME straight
/// to the host's PTP time. The host POSTs this right after resuming a restored
/// snapshot — the guest clock is frozen at snapshot time, so it lags by the paused
/// duration; stepping it now (rather than waiting for chrony's next poll) means the
/// first request after wake already sees correct time. chrony keeps disciplining.
async fn resync_clock_response(_req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let r = clock::resync_now();
    if r.ok {
        info!(detail = %r.detail, "clock resynced (direct PHC step)");
    } else {
        error!(detail = %r.detail, "clock resync failed");
    }
    let body = serde_json::json!({ "ok": r.ok, "detail": r.detail });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(serde_json::to_vec(&body).unwrap())))
        .unwrap()
}

async fn logs_response(
    state: &AgentState,
    req: &Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let query = req.uri().query().unwrap_or("");
    let param = |key: &str| -> Option<u64> {
        query
            .split('&')
            .find_map(|p| p.strip_prefix(key))
            .and_then(|v| v.parse().ok())
    };

    // `since` (incremental cursor) takes precedence over `limit` (tail). Read the
    // unified sink directly: it carries both server output and function egress
    // events under one `(boot_id, seq)` cursor space.
    let lines = if let Some(since) = param("since=") {
        state.log_sink.get_logs_since(since).await
    } else {
        let limit = param("limit=").unwrap_or(200) as usize;
        state.log_sink.get_logs(limit).await
    };

    let resp = jkbase_common::logs::LogsResponse {
        boot_id: state.log_sink.boot_id().to_string(),
        lines,
    };
    let body = serde_json::to_vec(&resp).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
        .unwrap()
}

/// `426 Upgrade Required` — a function backend is strictly request/response and cannot be
/// coerced into a long-lived/streaming connection (P0-INGRESS-UPGRADE). Long-lived traffic
/// must target a `server`.
fn upgrade_required_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::UPGRADE_REQUIRED)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from(
            "upgrade not supported on a function route; use a server backend",
        )))
        .unwrap()
}

/// `404 Not Found` for a declared-but-missing function route. Deliberately does NOT fall
/// through to static serving — a misspelled/undeployed function must not expose the static
/// site or the metadata image's `_`-prefixed control files.
fn not_found_response() -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::NOT_FOUND)
        .header("content-type", "text/plain")
        .body(Full::new(Bytes::from("not found")))
        .unwrap()
}

fn extract_function_name(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
    if parts.first() == Some(&"functions") {
        parts.get(1).map(|s| s.to_string())
    } else {
        None
    }
}

async fn proxy_to_server(
    port: u16,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let addr = format!("127.0.0.1:{port}");
    let path = req
        .uri()
        .path_and_query()
        .map(|pq| pq.as_str())
        .unwrap_or("/")
        .to_string();

    // Capture the client-side upgrade future before the body is consumed.
    let upgrade = jkbase_wsproxy::is_upgrade_request(req.headers());
    let client_upgrade = upgrade.then(|| hyper::upgrade::on(&mut req));

    let stream = match tokio::net::TcpStream::connect(&addr).await {
        Ok(s) => s,
        Err(e) => {
            error!(port, error = %e, "failed to connect to server");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("server not available")))
                .unwrap();
        }
    };

    let io = TokioIo::new(stream);
    let (mut sender, conn) = match hyper::client::conn::http1::handshake(io).await {
        Ok(pair) => pair,
        Err(e) => {
            error!(port, error = %e, "server handshake failed");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("server handshake failed")))
                .unwrap();
        }
    };
    // The connection future must keep running to drive an upgrade; with_upgrades()
    // lets the raw stream be reclaimed from the 101 response.
    if upgrade {
        tokio::spawn(async move {
            let _ = conn.with_upgrades().await;
        });
    } else {
        tokio::spawn(async move {
            let _ = conn.await;
        });
    }

    let mut builder = Request::builder().method(req.method()).uri(&path);
    for (key, value) in req.headers() {
        builder = builder.header(key, value);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    match sender.send_request(proxy_req).await {
        Ok(mut resp) if resp.status() == StatusCode::SWITCHING_PROTOCOLS => {
            use jkbase_wsproxy::UpgradeOutcome;
            // The edge proxy sanitizes headers before they reach the client; here we
            // just splice (the container is this tenant's own code — intra-tenant hop).
            match jkbase_wsproxy::spawn_upgrade_relay(
                client_upgrade,
                &mut resp,
                jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT,
                upgrade_permits(),
            ) {
                UpgradeOutcome::Relayed => {
                    let mut builder = Response::builder().status(StatusCode::SWITCHING_PROTOCOLS);
                    for (key, value) in resp.headers() {
                        builder = builder.header(key, value);
                    }
                    builder.body(Full::new(Bytes::new())).unwrap()
                }
                UpgradeOutcome::Unsolicited => {
                    error!("container sent 101 without a client upgrade request");
                    Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(Full::new(Bytes::from("unsolicited upgrade")))
                        .unwrap()
                }
                UpgradeOutcome::CapReached => {
                    error!("in-flight upgrade cap reached; refusing relay");
                    Response::builder()
                        .status(StatusCode::SERVICE_UNAVAILABLE)
                        .header("Retry-After", "5")
                        .body(Full::new(Bytes::from("too many concurrent upgrades")))
                        .unwrap()
                }
            }
        }
        Ok(resp) => {
            let status = resp.status();
            let headers = resp.headers().clone();
            let body = match resp.into_body().collect().await {
                Ok(b) => b.to_bytes(),
                Err(_) => Bytes::new(),
            };
            let mut builder = Response::builder().status(status);
            for (key, value) in &headers {
                builder = builder.header(key, value);
            }
            builder.body(Full::new(body)).unwrap()
        }
        Err(e) => {
            error!(port, error = %e, "server request failed");
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("server request failed")))
                .unwrap()
        }
    }
}

/// rhypedb's loopback native-TCP wire port inside the guest (see `start_database`).
const RHYPEDB_TCP_PORT: u16 = 4201;

/// In-VM ceiling on concurrent app→DB leg connections (both planes share it). Bounds the fd/task
/// footprint a tenant hammering its OWN loopback proxy can create — self-DoS of its own VM only
/// (the host gateway independently caps the DB-VM-facing relays), but cheap to bound.
const DB_LEG_MAX_CONNS: usize = 512;

/// P2 §7.6 — one in-guest loopback proxy listener for the app→DB leg. Binds
/// `127.0.0.1:local_port` (a rhypedb port the tenant's client already targets on a co-located
/// project) and, per accepted connection, dials the host DB gateway (`172.16.0.1:gateway_port`)
/// and byte-transparently splices. The gateway authenticates by our UNFORGEABLE source IP (the L2
/// source-guard pins {ip,mac}↔TAP) and forwards to the sibling DB VM. Best-effort: a bind failure
/// logs and disables that plane rather than crashing the agent; a per-connection dial failure
/// drops only that connection. Runs ONLY on a dedicated app VM, where these ports are free (no
/// co-located rhypedb). `permits` bounds concurrent connections across both planes.
async fn db_leg_loopback_proxy(
    local_port: u16,
    gateway_port: u16,
    permits: std::sync::Arc<tokio::sync::Semaphore>,
) {
    use tokio::io::copy_bidirectional;
    let listener = match TcpListener::bind(("127.0.0.1", local_port)).await {
        Ok(l) => l,
        Err(e) => {
            error!(error = %e, port = local_port, "app→DB leg: failed to bind loopback proxy");
            return;
        }
    };
    loop {
        let (mut local, _) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                // Back off briefly so a transient accept errno can't busy-spin the loop.
                error!(error = %e, port = local_port, "app→DB leg: accept error");
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
                continue;
            }
        };
        // Bound concurrent leg connections (self-DoS guard). At the cap, drop this connection.
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            continue;
        };
        tokio::spawn(async move {
            let _permit = permit; // released when this connection's splice ends
            let _ = local.set_nodelay(true);
            let mut up = match tokio::net::TcpStream::connect((
                jkbase_common::config::DB_GATEWAY_IP,
                gateway_port,
            ))
            .await
            {
                Ok(s) => s,
                Err(e) => {
                    error!(error = %e, gateway_port, "app→DB leg: dial host DB gateway failed");
                    return;
                }
            };
            let _ = up.set_nodelay(true);
            // Byte-transparent full-duplex splice. Propagates half-close; the DB wire has
            // server-initiated pushes (subscriptions), so this must NOT assume request/response.
            let _ = copy_bidirectional(&mut local, &mut up).await;
        });
    }
}

/// Map a HOST-set `x-jkbase-db-port` header VALUE to the rhypedb loopback port to splice to:
/// exactly `"4200"`/`"4201"` ⇒ that port, anything else ⇒ `None` so the splice fails closed rather
/// than being aimed at an arbitrary in-guest port. Absent-header handling (default to the native
/// wire `4201`, the external edge's behavior) is at the CALL site, so a header that is present but
/// unparseable/unknown can never silently default — it returns `None` → 400. The header is never
/// guest-controlled (see the caller).
fn db_splice_target_port(value: &str) -> Option<u16> {
    if value == RHYPEDB_TCP_PORT.to_string() {
        Some(RHYPEDB_TCP_PORT)
    } else if value == RHYPEDB_HTTP_PORT.to_string() {
        Some(RHYPEDB_HTTP_PORT)
    } else {
        None
    }
}

/// Constant-time byte compare for the splice-secret check (the agent has no other
/// const-time primitive; mirrors the edge/control-plane discipline).
fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

/// [R3] The managed-DB reach-plane backend leg. The edge does an HTTP/1.1 `Upgrade` to
/// `/_jkbase/db` presenting the per-deploy splice secret; on `101` the agent splices the
/// raw byte stream to rhypedb's loopback TCP wire (`127.0.0.1:4201`). The DB stays
/// loopback-only — this is the sole in-VM path to it, gated on the secret so one isolation
/// slip (a sibling reaching this eth0 port) isn't a direct splice into the unauthenticated
/// engine. Not an HTTP backend, so there is NO hyper handshake on the backend leg.
/// Verify the host→agent reach-plane secret ([R3]/[RB2]). No secret configured (no managed DB
/// / not baked) OR a mismatch ⇒ false, so every gated endpoint fails closed to 404 (never
/// confirming the endpoint or the DB's existence). Constant-time compare.
fn db_secret_ok(state: &AgentState, req: &Request<hyper::body::Incoming>) -> bool {
    let Some(expected) = state.db_splice_secret.as_deref() else {
        return false;
    };
    let presented = req
        .headers()
        .get("x-jkbase-db-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    ct_eq(presented.as_bytes(), expected.as_bytes())
}

async fn handle_db_splice(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    // Verify the host→agent secret. No secret / mismatch ⇒ 404, fail-closed.
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }

    // Which loopback DB port to splice to. The header is HOST-set (the external edge omits it →
    // the native wire; the app→DB host gateway sets it per leg), NEVER guest-controlled: an
    // external client only owns the raw bytes AFTER the 101, not this upgrade request's headers.
    // Fail closed on any value other than the two known rhypedb ports so this can never be aimed
    // at an arbitrary in-guest port. Absent ⇒ 4201 (the native wire), preserving the edge path.
    let target_port = match req.headers().get("x-jkbase-db-port") {
        None => RHYPEDB_TCP_PORT, // absent → native wire (external edge default, unchanged)
        Some(v) => match v.to_str().ok().and_then(db_splice_target_port) {
            Some(p) => p,
            None => {
                return Response::builder()
                    .status(StatusCode::BAD_REQUEST)
                    .body(Full::new(Bytes::from("bad db port")))
                    .unwrap();
            }
        },
    };

    // Require a real upgrade so a valid-secret non-upgrade request can't leak a permit on
    // an `on()` future that never resolves.
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }

    // Bound concurrent splices with the same intra-VM permit pool as WS upgrades.
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };

    // Connect the raw loopback wire BEFORE returning 101 (a connect failure must not leave
    // the edge spliced to nothing).
    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", target_port)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, port = target_port, "db splice: rhypedb loopback wire not available");
            return Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Full::new(Bytes::from("db not available")))
                .unwrap();
        }
    };
    let _ = jkbase_wsproxy::set_relay_keepalive(&backend);

    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let _permit = permit; // released when the relay ends
        match client_upgrade.await {
            Ok(upgraded) => {
                jkbase_wsproxy::relay_bidirectional(
                    TokioIo::new(upgraded),
                    backend,
                    jkbase_wsproxy::DEFAULT_RELAY_IDLE_TIMEOUT,
                )
                .await;
            }
            Err(e) => error!(error = %e, "db splice: client upgrade failed"),
        }
    });

    // 101 → the edge splices its (TLS) side to this upgraded stream.
    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// rhypedb's loopback HTTP admin port inside the guest (see `db_manifest`).
const RHYPEDB_HTTP_PORT: u16 = 4200;

/// A console DB tools op → the target route on rhypedb's OPEN loopback HTTP plane. The rhypedb
/// path is HARD-CODED per variant (never derived from the host request), so `/admin/*` — which
/// would need the admin token anyway — is unreachable through this seam.
#[derive(Clone, Copy)]
enum DbHttpOp {
    Query,
    Schema,
    Status,
}

impl DbHttpOp {
    fn method(self) -> &'static str {
        match self {
            DbHttpOp::Query => "POST",
            DbHttpOp::Schema | DbHttpOp::Status => "GET",
        }
    }
    fn rhypedb_path(self) -> &'static str {
        match self {
            DbHttpOp::Query => "/query",
            DbHttpOp::Schema => "/schema",
            DbHttpOp::Status => "/status",
        }
    }
    fn forwards_body(self) -> bool {
        matches!(self, DbHttpOp::Query)
    }
}

/// Max inbound query body the agent accepts before forwarding to the engine.
const MAX_DB_QUERY_IN_BYTES: usize = 256 * 1024;
/// Max engine response the agent buffers before relaying to the host (result rows are
/// governor-bounded engine-side; this caps a pathological payload).
const MAX_DB_QUERY_OUT_BYTES: usize = 16 * 1024 * 1024;

/// Console DB proxy ([managed-rhypedb studio]). Forward a secret-gated host request to rhypedb's
/// OPEN loopback HTTP plane (`/query` | `/schema` | `/status`; NEVER `/admin/*`) and relay the
/// engine's status + JSON body back. Bounded in + out; concurrency-capped by the shared upgrade
/// permit pool. Lets the console query/introspect the DB without ever exposing it off-loopback.
async fn handle_db_query(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
    op: DbHttpOp,
) -> Response<Full<Bytes>> {
    use http_body_util::{BodyExt, Limited};
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    let Ok(_permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };

    // Read the (bounded) inbound body only for the write/query op; schema/status are GET.
    let body = if op.forwards_body() {
        match Limited::new(req.into_body(), MAX_DB_QUERY_IN_BYTES)
            .collect()
            .await
        {
            Ok(c) => c.to_bytes(),
            Err(_) => {
                return Response::builder()
                    .status(StatusCode::PAYLOAD_TOO_LARGE)
                    .body(Full::new(Bytes::from("query too large")))
                    .unwrap();
            }
        }
    } else {
        Bytes::new()
    };

    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_HTTP_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "db query: rhypedb loopback http not available");
            return bad_gateway("db not available");
        }
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(backend)).await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "db query: loopback handshake failed");
                return bad_gateway("db handshake failed");
            }
        };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let rreq = Request::builder()
        .method(op.method())
        .uri(op.rhypedb_path())
        .header("host", "127.0.0.1")
        .header("content-type", "application/json")
        .body(Full::new(body))
        .unwrap();
    let resp = match sender.send_request(rreq).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "db query: engine request failed");
            return bad_gateway("db request failed");
        }
    };
    let status = resp.status();
    let out = match Limited::new(resp.into_body(), MAX_DB_QUERY_OUT_BYTES)
        .collect()
        .await
    {
        Ok(c) => c.to_bytes(),
        Err(_) => return bad_gateway("db response too large"),
    };
    Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(out))
        .unwrap()
}

/// Hard cap on a restore tar the host may push ([RB3]) — defense-in-depth so even a
/// host-authenticated push can't fill the data disk unbounded. The disk itself is the real
/// bound; this fails fast well before an accidental runaway.
const MAX_RESTORE_BYTES: u64 = 64 * 1024 * 1024 * 1024;

/// [RB2]/[RB3] Managed-DB backup PULL. The host does an HTTP/1.1 `Upgrade` to
/// `/_jkbase/db/backup` presenting the splice secret; the agent authorizes the loopback
/// `GET /admin/backup/stream` with the reserved admin token ([RB1]) and streams the tar back
/// over the upgraded socket, DE-CHUNKED and never buffered ([RB3]). The host validates the tar
/// end-of-archive marker before committing the object ([RB8]); a truncated relay = a failed
/// backup. The admin token never leaves the guest — only the opaque tar bytes do.
async fn handle_db_backup(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    use tokio::io::AsyncWriteExt;
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    // Need the reserved admin token to authorize the loopback admin call; absent ⇒ 404
    // (no managed DB / not baked), fail-closed.
    let Some(admin_token) = state.db_admin_token.clone() else {
        return not_found_response();
    };
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };

    // Connect + send the admin request BEFORE returning 101, so a DB-down / auth failure is a
    // clean non-101 error to the host rather than an empty upgraded stream.
    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_HTTP_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "db backup: rhypedb loopback http not available");
            return bad_gateway("db not available");
        }
    };
    let (mut sender, conn) =
        match hyper::client::conn::http1::handshake(TokioIo::new(backend)).await {
            Ok(p) => p,
            Err(e) => {
                error!(error = %e, "db backup: loopback handshake failed");
                return bad_gateway("db handshake failed");
            }
        };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let admin_req = Request::builder()
        .method("GET")
        .uri("/admin/backup/stream")
        .header("host", "127.0.0.1")
        .header("authorization", format!("Bearer {admin_token}"))
        .body(Full::new(Bytes::new()))
        .unwrap();
    let resp = match sender.send_request(admin_req).await {
        Ok(r) => r,
        Err(e) => {
            error!(error = %e, "db backup: admin request failed");
            return bad_gateway("db backup request failed");
        }
    };
    if resp.status() != StatusCode::OK {
        error!(status = %resp.status(), "db backup: admin returned non-200");
        return bad_gateway("db backup unavailable");
    }

    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        let _permit = permit; // released when the relay ends
        // Keep the loopback connection driver alive by moving `sender` in (dropping it early
        // could cancel the in-flight response body).
        let _sender = sender;
        match client_upgrade.await {
            Ok(upgraded) => {
                let mut out = TokioIo::new(upgraded);
                let mut body = resp.into_body();
                let mut clean = true;
                loop {
                    match body.frame().await {
                        Some(Ok(frame)) => {
                            if let Some(chunk) = frame.data_ref()
                                && out.write_all(chunk).await.is_err()
                            {
                                clean = false;
                                break;
                            }
                        }
                        Some(Err(e)) => {
                            error!(error = %e, "db backup: body stream error");
                            clean = false;
                            break;
                        }
                        None => break,
                    }
                }
                // Half-close so the host sees a clean EOF = end of the tar. A mid-stream error
                // truncates the body → the host's tar-EOF validation rejects it ([RB8]).
                let _ = out.shutdown().await;
                if !clean {
                    tracing::warn!(
                        "db backup: tar stream ended early (host will reject as truncated)"
                    );
                }
            }
            Err(e) => error!(error = %e, "db backup: client upgrade failed"),
        }
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db-backup")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// [RB2]/[RB3]/[RB5] Managed-DB restore PUSH. The host Upgrades to `/_jkbase/db/restore`
/// (splice-secret gated) and streams a backup tar; the agent untars it IN-GUEST (the host
/// never writes the data-disk FS — [RB5]), atomically stages a complete snapshot, respawns
/// rhypedb with `RHYPEDB_RESTORE_FROM`, waits for it to serve again, then reports `ok` /
/// `err: …` back over the socket so the host records the outcome.
async fn handle_db_restore(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    if !db_secret_ok(&state, &req) {
        return not_found_response();
    }
    if !Path::new("/mnt/data").exists() {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .body(Full::new(Bytes::from("no data disk")))
            .unwrap();
    }
    if !jkbase_wsproxy::is_upgrade_request(req.headers()) {
        return Response::builder()
            .status(StatusCode::BAD_REQUEST)
            .body(Full::new(Bytes::from("expected upgrade")))
            .unwrap();
    }
    let Ok(permit) = upgrade_permits().clone().try_acquire_owned() else {
        return Response::builder()
            .status(StatusCode::SERVICE_UNAVAILABLE)
            .header("retry-after", "5")
            .body(Full::new(Bytes::from("too many concurrent db connections")))
            .unwrap();
    };
    let admin_token = state.db_admin_token.clone();
    let client_upgrade = hyper::upgrade::on(&mut req);
    tokio::spawn(async move {
        use tokio::io::AsyncWriteExt;
        let _permit = permit;
        let upgraded = match client_upgrade.await {
            Ok(u) => u,
            Err(e) => {
                error!(error = %e, "db restore: client upgrade failed");
                return;
            }
        };
        let mut io = TokioIo::new(upgraded);
        let result = perform_restore(&state.containers, admin_token.as_deref(), &mut io).await;
        let line = match &result {
            Ok(()) => "ok\n".to_string(),
            Err(e) => {
                error!(error = %e, "db restore failed");
                format!("err: {e}\n")
            }
        };
        let _ = io.write_all(line.as_bytes()).await;
        let _ = io.shutdown().await;
    });

    Response::builder()
        .status(StatusCode::SWITCHING_PROTOCOLS)
        .header("connection", "upgrade")
        .header("upgrade", "jkbase-db-restore")
        .body(Full::new(Bytes::new()))
        .unwrap()
}

/// Drive one restore: stream the tar off `io` to a temp file (bounded, never in RAM), untar
/// it traversal-safe into a fresh staging dir, require a complete snapshot (its
/// `MANIFEST.json`), atomically publish it, then respawn rhypedb to restore-on-boot and wait
/// for it to serve. On success clears the staging + resets the DB manifest ([RB9]).
async fn perform_restore<S>(
    containers: &Arc<ContainerSupervisor>,
    admin_token: Option<&str>,
    io: &mut S,
) -> Result<()>
where
    S: tokio::io::AsyncRead + Unpin,
{
    use tokio::io::AsyncReadExt;
    let base = PathBuf::from("/mnt/data/volumes/rhypedb-restore");
    let incoming = base.join(".incoming");
    let snapshot = base.join("snapshot");
    let tar_path = base.join(".incoming.tar");
    std::fs::create_dir_all(&base).context("create restore volume dir")?;
    let _ = std::fs::remove_dir_all(&incoming);
    let _ = std::fs::remove_file(&tar_path);

    // Stream the pushed tar → temp file on the data disk (bounded by MAX_RESTORE_BYTES; the
    // host half-closes after the archive, so read-to-EOF yields the whole tar).
    {
        let mut f = tokio::fs::File::create(&tar_path)
            .await
            .context("create restore tar")?;
        let mut buf = vec![0u8; 64 * 1024];
        let mut total: u64 = 0;
        loop {
            let n = io.read(&mut buf).await.context("read restore stream")?;
            if n == 0 {
                break;
            }
            total += n as u64;
            if total > MAX_RESTORE_BYTES {
                let _ = tokio::fs::remove_file(&tar_path).await;
                anyhow::bail!("restore stream exceeds {MAX_RESTORE_BYTES} bytes");
            }
            tokio::io::AsyncWriteExt::write_all(&mut f, &buf[..n])
                .await
                .context("write restore tar")?;
        }
        tokio::io::AsyncWriteExt::flush(&mut f)
            .await
            .context("flush restore tar")?;
    }

    // Untar traversal-safe (the `tar` crate refuses `..`/absolute escapes) on the blocking
    // pool. Then require a complete snapshot before publishing it.
    let incoming_c = incoming.clone();
    let tar_c = tar_path.clone();
    tokio::task::spawn_blocking(move || -> Result<()> {
        std::fs::create_dir_all(&incoming_c)?;
        let f = std::fs::File::open(&tar_c)?;
        let mut ar = tar::Archive::new(f);
        ar.set_preserve_permissions(false);
        ar.unpack(&incoming_c).context("untar restore snapshot")?;
        Ok(())
    })
    .await
    .context("untar task join")??;
    let _ = std::fs::remove_file(&tar_path);
    // Require a COMPLETE snapshot (MANIFEST.json + every listed SST + wal.log + schema.rhype),
    // not just a MANIFEST.json — a stream truncated at a tar-entry boundary after MANIFEST but
    // before an SST unpacks cleanly yet is unrestorable. Publishing it would brick the DB boot
    // (rhypedb fail-closes, and db_manifest would re-arm the restore every boot). Refuse instead,
    // so the DB simply boots its pre-restore data.
    if !container_supervisor::snapshot_is_complete(&incoming) {
        let _ = std::fs::remove_dir_all(&incoming);
        anyhow::bail!("pushed archive is not a complete backup (truncated / missing files)");
    }

    // Atomically publish: only a complete snapshot ever becomes `snapshot/`, so a partial
    // untar can never trigger a restore that would brick the DB boot.
    let _ = std::fs::remove_dir_all(&snapshot);
    std::fs::rename(&incoming, &snapshot).context("publish restore snapshot")?;

    // Respawn the DB to restore-on-boot, then wait for it to serve again.
    containers.restore_database(admin_token).await?;
    if !wait_db_healthy(std::time::Duration::from_secs(300)).await {
        anyhow::bail!("managed DB did not become healthy after restore");
    }
    containers.finalize_restore(admin_token).await;
    Ok(())
}

/// Poll the loopback DB `/health` until it serves 200 (⟹ rhypedb finished restore-on-boot and
/// opened the database) or the deadline passes.
async fn wait_db_healthy(timeout: std::time::Duration) -> bool {
    let deadline = std::time::Instant::now() + timeout;
    while std::time::Instant::now() < deadline {
        if db_health_probe().await {
            return true;
        }
        tokio::time::sleep(std::time::Duration::from_millis(500)).await;
    }
    false
}

async fn db_health_probe() -> bool {
    let Ok(stream) = tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_HTTP_PORT)).await else {
        return false;
    };
    let Ok((mut sender, conn)) = hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    else {
        return false;
    };
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let req = Request::builder()
        .method("GET")
        .uri("/health")
        .header("host", "127.0.0.1")
        .body(Full::new(Bytes::new()))
        .unwrap();
    matches!(sender.send_request(req).await, Ok(r) if r.status() == StatusCode::OK)
}

fn bad_gateway(msg: &'static str) -> Response<Full<Bytes>> {
    Response::builder()
        .status(StatusCode::BAD_GATEWAY)
        .body(Full::new(Bytes::from(msg)))
        .unwrap()
}

/// Bound on concurrent in-flight relayed upgrades inside this agent (one tenant VM).
/// A relay holds a permit for its lifetime, so a flood of cheap WebSocket holds can't
/// pin unbounded fds + relay tasks. (Sanitization + the edge-wide cap live at the
/// proxy; this is the intra-VM backstop.)
fn upgrade_permits() -> &'static Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(256)));
    &PERMITS
}

/// Bound on concurrent function invocations inside this agent (one tenant VM). Caps the
/// peak CPU/threads/memory a flood of (possibly slow, fuel-heavy) functions can pin in the
/// process that also serves this project's sites + servers. Waiters queue rather than 503.
fn function_permits() -> &'static Arc<tokio::sync::Semaphore> {
    static PERMITS: std::sync::LazyLock<Arc<tokio::sync::Semaphore>> =
        std::sync::LazyLock::new(|| Arc::new(tokio::sync::Semaphore::new(32)));
    &PERMITS
}

/// Max request body bytes marshalled into a function (matches the response cap). The body
/// is fully buffered here, upstream of the runtime, so the bound belongs here.
const MAX_REQUEST_BODY: usize = 10 * 1024 * 1024;

async fn invoke_function(
    state: Arc<AgentState>,
    name: &str,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let method = req.method().to_string();
    let path = req.uri().path().to_string();
    let query = req.uri().query().unwrap_or("").to_string();
    let headers: Vec<(String, String)> = req
        .headers()
        .iter()
        .map(|(k, v)| (k.to_string(), v.to_str().unwrap_or("").to_string()))
        .collect();

    let body = match Limited::new(req.into_body(), MAX_REQUEST_BODY)
        .collect()
        .await
    {
        Ok(b) => b.to_bytes().to_vec(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::PAYLOAD_TOO_LARGE)
                .body(Full::new(Bytes::from("request body too large")))
                .unwrap();
        }
    };

    let func_req = FunctionRequest {
        method,
        path,
        query,
        headers,
        body,
    };

    // Hold a concurrency permit for the duration of the invocation (see function_permits).
    let _permit = function_permits()
        .clone()
        .acquire_owned()
        .await
        .expect("function semaphore is never closed");

    let func_resp = match state.functions.invoke(name, func_req).await {
        Ok(r) => r,
        Err(e) => {
            // Log the detail server-side; return a GENERIC body — the error string can carry
            // request-derived data (headers/paths a caller controls) and must not be
            // reflected back from the platform-trusted agent (review H1).
            error!(function = name, error = %e, "function invocation error");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("function error")))
                .unwrap();
        }
    };

    let mut builder = Response::builder().status(func_resp.status);
    for (key, value) in &func_resp.headers {
        builder = builder.header(key.as_str(), value.as_str());
    }
    builder
        .body(Full::new(Bytes::from(func_resp.body)))
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn db_splice_target_port_is_host_set_and_fail_closed() {
        // The two known rhypedb loopback ports the app→DB gateway may target.
        assert_eq!(db_splice_target_port("4201"), Some(RHYPEDB_TCP_PORT));
        assert_eq!(db_splice_target_port("4200"), Some(RHYPEDB_HTTP_PORT));
        // Anything else ⇒ None → the caller fails closed with 400; never aimable at an arbitrary
        // in-guest port. (Absent-header default-to-4201 is the call site's job, not this helper's,
        // so a present-but-unparseable/unknown value can't silently default.)
        assert_eq!(db_splice_target_port("22"), None);
        assert_eq!(db_splice_target_port("9090"), None);
        assert_eq!(db_splice_target_port(""), None);
        assert_eq!(db_splice_target_port("4201 "), None);
        assert_eq!(db_splice_target_port("04201"), None);
    }

    #[test]
    fn route_config_maps_kinds_and_drops_unknown() {
        let dir = std::env::temp_dir().join(format!("jkagent-routes-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // server + function are typed; an unknown service is dropped (fail-closed), never
        // silently treated as a server.
        std::fs::write(
            dir.join("_routes.json"),
            r#"{
              "/api": {"service":"function","name":"api"},
              "/":    {"service":"server","name":"web"},
              "/x":   {"service":"bogus","name":"x"}
            }"#,
        )
        .unwrap();
        let routes = load_route_config(&dir);
        assert_eq!(routes.len(), 2, "the unknown-service route must be dropped");
        let api = routes.iter().find(|r| r.prefix == "/api").unwrap();
        assert_eq!(api.kind, RouteKind::Function);
        assert_eq!(api.name, "api");
        let web = routes.iter().find(|r| r.prefix == "/").unwrap();
        assert_eq!(web.kind, RouteKind::Server);
        assert!(!routes.iter().any(|r| r.prefix == "/x"));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn function_name_extraction() {
        assert_eq!(
            extract_function_name("/functions/hello"),
            Some("hello".into())
        );
        assert_eq!(
            extract_function_name("/functions/hello/world"),
            Some("hello".into())
        );
        assert_eq!(extract_function_name("/api/foo"), None);
        assert_eq!(extract_function_name("/"), None);
    }
}
