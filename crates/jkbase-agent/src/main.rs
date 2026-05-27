mod function_runtime;
mod static_server;

use anyhow::Result;
use function_runtime::{FunctionRequest, FunctionRuntime};
use http_body_util::Full;
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

fn is_pid1() -> bool {
    std::process::id() == 1
}

struct AgentState {
    serve_dir: PathBuf,
    functions: FunctionRuntime,
}

#[tokio::main]
async fn main() -> Result<()> {
    if is_pid1() {
        mount_filesystems();
    }

    tracing_subscriber::fmt::init();

    let serve_dir = PathBuf::from(
        std::env::var("JKBASE_SERVE_DIR").unwrap_or_else(|_| "/srv/www".to_string()),
    );
    let functions_dir = PathBuf::from(
        std::env::var("JKBASE_FUNCTIONS_DIR")
            .unwrap_or_else(|_| serve_dir.join("_functions").to_string_lossy().to_string()),
    );

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

    let port: u16 = std::env::var("JKBASE_PORT")
        .unwrap_or_else(|_| "80".to_string())
        .parse()?;

    let state = Arc::new(AgentState {
        serve_dir,
        functions,
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

async fn handle_request(
    state: Arc<AgentState>,
    req: Request<hyper::body::Incoming>,
) -> Result<Response<Full<Bytes>>, hyper::Error> {
    let path = req.uri().path().to_string();

    // Check if this is a function call: /functions/{name} or /functions/{name}/...
    if let Some(func_name) = extract_function_name(&path) {
        if state.functions.has_function(&func_name) {
            return Ok(invoke_function(state, &func_name, req).await);
        }
    }

    // Fall through to static file serving
    static_server::handle_static(&state.serve_dir, req).await
}

fn extract_function_name(path: &str) -> Option<String> {
    let parts: Vec<&str> = path.trim_start_matches('/').splitn(3, '/').collect();
    if parts.first() == Some(&"functions") {
        parts.get(1).map(|s| s.to_string())
    } else {
        None
    }
}

async fn invoke_function(
    state: Arc<AgentState>,
    name: &str,
    req: Request<hyper::body::Incoming>,
) -> Response<Full<Bytes>> {
    use http_body_util::BodyExt;

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
