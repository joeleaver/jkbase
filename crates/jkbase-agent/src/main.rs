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

/// Read the host-written `_db_reach.json` splice secret ([R3]) from the metadata image.
/// Absent/malformed/empty ⇒ `None` (no managed DB, or fail-closed) → `/_jkbase/db` is
/// then unreachable, never open.
fn load_db_splice_secret(serve_dir: &Path) -> Option<String> {
    let path = serve_dir.join(jkbase_common::config::DbReachFacts::FILE);
    let bytes = std::fs::read(&path).ok()?;
    let facts: jkbase_common::config::DbReachFacts = serde_json::from_slice(&bytes).ok()?;
    (!facts.splice_secret.is_empty()).then_some(facts.splice_secret)
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
    if let Some(lowerdirs) = db_lowerdirs {
        let schema_path = serve_dir.join("_database/schema.rhype");
        match std::fs::read(&schema_path) {
            Ok(schema) => {
                let rules = std::fs::read(serve_dir.join("_database/rules.rhype")).ok();
                if let Err(e) = containers
                    .start_database(&schema, rules.as_deref(), lowerdirs)
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

    let db_splice_secret = load_db_splice_secret(&serve_dir);
    let state = Arc::new(AgentState {
        serve_dir,
        functions_dir,
        functions,
        containers,
        log_sink,
        route_config,
        sites,
        db_splice_secret,
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
        return static_server::handle_static_with_path(&site.root, &path, site.spa).await;
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
                return static_server::handle_static_with_path(&site.root, &sub_path, site.spa)
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
async fn handle_db_splice(
    state: Arc<AgentState>,
    mut req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    // Verify the host→agent secret. No secret configured (no managed DB / not baked) OR a
    // mismatch ⇒ 404, fail-closed (never confirm the endpoint or the DB's existence).
    let Some(expected) = state.db_splice_secret.as_deref() else {
        return not_found_response();
    };
    let presented = req
        .headers()
        .get("x-jkbase-db-secret")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    if !ct_eq(presented.as_bytes(), expected.as_bytes()) {
        return not_found_response();
    }

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
    let backend = match tokio::net::TcpStream::connect(("127.0.0.1", RHYPEDB_TCP_PORT)).await {
        Ok(s) => s,
        Err(e) => {
            error!(error = %e, "db splice: rhypedb loopback wire not available");
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
