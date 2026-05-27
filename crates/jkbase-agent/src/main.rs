mod container_supervisor;
mod function_runtime;
mod static_server;

use anyhow::Result;
use container_supervisor::ContainerSupervisor;
use function_runtime::{FunctionRequest, FunctionRuntime};
use http_body_util::{BodyExt, Full};
use hyper::body::Bytes;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use std::net::SocketAddr;
use std::path::PathBuf;
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
    ];

    for (target, fstype, source) in &mounts {
        let _ = std::fs::create_dir_all(target);
        let src = CString::new(*source).unwrap();
        let tgt = CString::new(*target).unwrap();
        let fst = CString::new(*fstype).unwrap();
        unsafe {
            libc::mount(
                src.as_ptr(),
                tgt.as_ptr(),
                fst.as_ptr(),
                0,
                ptr::null(),
            );
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

    let flags = 0;
    let ret = unsafe { libc::mount(src.as_ptr(), tgt.as_ptr(), fst.as_ptr(), flags, ptr::null()) };
    if ret != 0 {
        eprintln!(
            "failed to mount {device} at {target}: {}",
            std::io::Error::last_os_error()
        );
    }
}

fn is_pid1() -> bool {
    std::process::id() == 1
}

struct AgentState {
    serve_dir: PathBuf,
    functions_dir: PathBuf,
    functions: FunctionRuntime,
    containers: Arc<ContainerSupervisor>,
    route_config: Vec<RouteEntry>,
    sites: Vec<SiteEntry>,
}

struct RouteEntry {
    prefix: String,
    server_name: String,
}

struct SiteEntry {
    name: String,
    root: PathBuf,
    prefix: String,
    spa: bool,
}

#[tokio::main]
async fn main() -> Result<()> {
    if is_pid1() {
        mount_filesystems();
        seed_entropy();
    }

    tracing_subscriber::fmt::init();

    let serve_dir = PathBuf::from(
        std::env::var("JKBASE_SERVE_DIR").unwrap_or_else(|_| "/srv/www".to_string()),
    );
    let functions_dir = PathBuf::from(
        std::env::var("JKBASE_FUNCTIONS_DIR")
            .unwrap_or_else(|_| serve_dir.join("_functions").to_string_lossy().to_string()),
    );
    let servers_dir = serve_dir.join("_servers");

    if is_pid1() {
        mount_content_drive(serve_dir.to_str().unwrap_or("/srv/www"));
    }

    let mut functions = FunctionRuntime::new();
    if let Err(e) = functions.load_all_from_dir(&functions_dir) {
        error!(error = %e, "failed to load functions");
    }

    let func_names = functions.list_functions();
    if !func_names.is_empty() {
        info!(functions = ?func_names, "loaded WASM functions");
    }

    let containers = Arc::new(ContainerSupervisor::new(servers_dir));
    if let Err(e) = containers.start_all().await {
        error!(error = %e, "failed to start server containers");
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

    if containers.has_servers() {
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
        route_config,
        sites,
    });

    info!("jkbase-agent starting (pid {})", std::process::id());
    info!(port, "listening");

    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await?;

    loop {
        let (stream, _peer) = listener.accept().await?;
        let state = state.clone();
        tokio::spawn(async move {
            let io = TokioIo::new(stream);
            let svc = service_fn(move |req| handle_request(state.clone(), req));
            if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
                error!(error = %e, "connection error");
            }
        });
    }
}

fn load_sites_config(serve_dir: &PathBuf) -> Vec<SiteEntry> {
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

fn load_route_config(serve_dir: &PathBuf) -> Vec<RouteEntry> {
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
        .filter(|(_, target)| target.service == "server")
        .map(|(prefix, target)| RouteEntry {
            prefix: prefix.clone(),
            server_name: target.name.clone(),
        })
        .collect()
}

async fn handle_request(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    if path == "/_jkbase/health" {
        return Ok(health_response(&state).await);
    }

    if path == "/_jkbase/logs" || path.starts_with("/_jkbase/logs?") {
        return Ok(logs_response(&state, &req).await);
    }

    // Check route config for server routing
    for route in &state.route_config {
        let prefix = route.prefix.trim_end_matches('*');
        if path.starts_with(prefix) {
            if let Some(port) = state.containers.get_server_for_route(&route.server_name).await {
                return Ok(proxy_to_server(port, req).await);
            }
        }
    }

    // Check if this is a function call
    if let Some(func_name) = extract_function_name(&path) {
        if state.functions.has_function(&func_name) {
            info!(function = %func_name, path = %path, "routing to function");
            return Ok(invoke_function(state, &func_name, req).await);
        }
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

    // Fall through to default static file serving
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
    });
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(
            serde_json::to_vec_pretty(&body).unwrap(),
        )))
        .unwrap()
}

async fn logs_response(
    state: &AgentState,
    req: &Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    let query = req.uri().query().unwrap_or("");
    let limit: usize = query
        .split('&')
        .find_map(|p| p.strip_prefix("limit="))
        .and_then(|v| v.parse().ok())
        .unwrap_or(200);

    let logs = state.containers.get_logs(limit).await;
    let body = serde_json::to_vec(&logs).unwrap_or_default();
    Response::builder()
        .status(StatusCode::OK)
        .header("Content-Type", "application/json")
        .body(Full::new(Bytes::from(body)))
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

async fn proxy_to_server(port: u16, req: Request<hyper::body::Incoming>) -> Response<Full<Bytes>> {
    let addr = format!("127.0.0.1:{port}");
    let path = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");

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
    tokio::spawn(conn);

    let mut builder = Request::builder().method(req.method()).uri(path);
    for (key, value) in req.headers() {
        builder = builder.header(key, value);
    }
    let proxy_req = builder.body(req.into_body()).unwrap();

    match sender.send_request(proxy_req).await {
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

    let body = match req.into_body().collect().await {
        Ok(b) => b.to_bytes().to_vec(),
        Err(e) => {
            error!(error = %e, "failed to read request body");
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Full::new(Bytes::from("failed to read body")))
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

    let func_resp = {
        let name = name.to_string();
        let state = state.clone();
        tokio::task::spawn_blocking(move || state.functions.invoke(&name, func_req)).await
    };

    let func_resp = match func_resp {
        Ok(Ok(r)) => r,
        Ok(Err(e)) => {
            error!(function = name, error = %e, "function invocation error");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from(format!("function error: {e}"))))
                .unwrap();
        }
        Err(e) => {
            error!(function = name, error = %e, "function task panicked");
            return Response::builder()
                .status(StatusCode::INTERNAL_SERVER_ERROR)
                .body(Full::new(Bytes::from("internal error")))
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
