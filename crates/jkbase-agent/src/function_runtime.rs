//! In-VM function runtime. Two execution paths run side by side, indefinitely:
//!
//!   * **wasip1** (legacy) — a core `_start` command module fed the request as JSON
//!     on stdin, returning the response as JSON on stdout. No sockets/fs/env *by
//!     construction*; a hermetic compute box.
//!   * **`wasi:http`** (component model) — a WASI 0.2 component exporting
//!     `wasi:http/incoming-handler@0.2.0` (the `wasi:http/proxy` world). This is the
//!     universal ABI every componentizer (cargo-component, ComponentizeJS,
//!     componentize-py, TinyGo) targets, so one host integration serves all languages.
//!
//! The component path is **purely additive**: Wasmtime still runs the legacy core
//! modules, and `load_all_from_dir` classifies each artifact (manifest-authoritative,
//! cross-checked against the wasm preamble) and dispatches.
//!
//! **Threat model — this runs untrusted tenant code inside the platform-trusted agent
//! process, which serves *all* of that project's requests.** Two invariants are
//! load-bearing:
//!
//!   * **P0 — egress is OFF, structurally.** The `wasi:http/proxy` world *imports*
//!     `outgoing-handler`, so a standard component won't instantiate if it is left
//!     unbound — therefore we link it but route every outbound request through an
//!     overridden [`WasiHttpView::send_request`] that returns an error **before any
//!     socket is opened** (the only code path that opens an outbound socket,
//!     `default_send_request`, is never reached). Belt-and-suspenders: the `WasiCtx`
//!     denies TCP/UDP/DNS and registers a deny-all `socket_addr_check`, and has **zero
//!     preopens** (no ambient filesystem). Granting real egress is the deferred
//!     host-mediated, default-deny, SSRF-guarded outbound-I/O arc — not here.
//!   * **P0 — a bad function cannot hang or exhaust the agent.** Every invocation is
//!     bounded by the kill-switch trio: per-invocation **fuel** (CPU), an **epoch**
//!     deadline driven by a shared background ticker (interrupts tight loops even when
//!     fuel is generous), and an **outer wall-clock timeout** (covers a guest parked in
//!     a host call, where fuel does not tick). `StoreLimits` caps guest memory, the
//!     request/response bodies are size-capped, and each call gets a fresh
//!     `Store`+`ResourceTable` so no state bleeds between invocations.

use anyhow::{Context, Result, bail};
use bytes::Bytes;
use http_body_util::combinators::BoxBody;
use http_body_util::{BodyExt, Full, Limited};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashMap};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tracing::{error, info, warn};
use wasmtime::component::{Component, Linker as ComponentLinker, ResourceTable};
use wasmtime::{Config, Engine, Linker, Module, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::p2::pipe::{MemoryInputPipe, MemoryOutputPipe};
use wasmtime_wasi::p2::{IoView, WasiCtx, WasiCtxBuilder, WasiView};
use wasmtime_wasi::preview1::{self, WasiP1Ctx};
use wasmtime_wasi_http::bindings::ProxyPre;
use wasmtime_wasi_http::bindings::http::types::{ErrorCode, Scheme};
use wasmtime_wasi_http::body::HyperOutgoingBody;
use wasmtime_wasi_http::types::{HostFutureIncomingResponse, OutgoingRequestConfig};
use wasmtime_wasi_http::{HttpResult, WasiHttpCtx, WasiHttpView};

/// Per-invocation fuel budget (CPU). Generous — the epoch + wall-clock bounds are the
/// real backstops; fuel mainly defangs the cheapest tight loops without a syscall.
const FUNCTION_FUEL: u64 = 1_000_000_000;
/// Guest linear-memory ceiling per invocation.
const FUNCTION_MEMORY_MAX: usize = 128 * 1024 * 1024;
/// Outer wall-clock bound on a single invocation (covers host-call parks epoch can't see).
const FUNCTION_WALL_TIMEOUT: Duration = Duration::from_secs(30);
/// Epoch ticker period. Epoch deadline = `FUNCTION_WALL_TIMEOUT / EPOCH_TICK` ticks.
const EPOCH_TICK: Duration = Duration::from_millis(10);
/// Max bytes accepted from a function's response body (matches the request cap in main.rs).
pub const MAX_RESPONSE_BODY: usize = 10 * 1024 * 1024;

/// Epoch deadline in ticks, derived from the wall-clock budget + tick period.
fn epoch_deadline_ticks() -> u64 {
    (FUNCTION_WALL_TIMEOUT.as_millis() / EPOCH_TICK.as_millis()).max(1) as u64
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionRequest {
    pub method: String,
    pub path: String,
    pub query: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FunctionResponse {
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl FunctionResponse {
    pub fn error(status: u16, message: &str) -> Self {
        Self {
            status,
            headers: vec![("content-type".to_string(), "text/plain".to_string())],
            body: message.as_bytes().to_vec(),
        }
    }
}

/// Declared runtime kind for a function. Closed set — anything else is rejected at load
/// (fail-closed), never silently defaulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RuntimeKind {
    /// Legacy wasip1 core command module (`_start` + stdin/stdout JSON).
    Wasip1,
    /// WASI 0.2 component exporting `wasi:http/incoming-handler`.
    WasiHttp,
}

impl RuntimeKind {
    /// Parse the `runtime` manifest field. `wasi-http` (default) | `wasip1`.
    fn parse(s: &str) -> Result<Self> {
        match s {
            "wasi-http" => Ok(Self::WasiHttp),
            "wasip1" => Ok(Self::Wasip1),
            other => bail!("unknown function runtime {other:?} (expected `wasi-http` or `wasip1`)"),
        }
    }
}

/// Host-written sidecar next to a function's `.wasm` (`_functions/{name}.json`). Carries
/// the authoritative runtime kind and the project secrets injected as env (populated in
/// the per-VM metadata image only — never on the on-disk artifact). Absent in P0 / for
/// hand-placed functions, in which case classification falls back to the preamble sniff
/// and env is empty.
#[derive(Debug, Default, Deserialize)]
struct FunctionSidecar {
    #[serde(default)]
    runtime: Option<String>,
    #[serde(default)]
    env: BTreeMap<String, String>,
}

/// Classify a wasm blob by its 8-byte preamble: `\0asm` magic + a u16 version and a u16
/// **layer** (0 = core module, 1 = component). Unambiguous in the binary format.
fn classify_preamble(bytes: &[u8]) -> Option<RuntimeKind> {
    if bytes.len() < 8 || &bytes[0..4] != b"\0asm" {
        return None;
    }
    match u16::from_le_bytes([bytes[6], bytes[7]]) {
        0 => Some(RuntimeKind::Wasip1),
        1 => Some(RuntimeKind::WasiHttp),
        _ => None,
    }
}

/// Resolve the authoritative runtime kind. The manifest wins when present, but a
/// disagreement with the preamble is rejected (a tenant must not be able to declare one
/// kind and ship another). Without a manifest, the preamble decides.
fn resolve_kind(declared: Option<RuntimeKind>, bytes: &[u8]) -> Result<RuntimeKind> {
    let sniffed = classify_preamble(bytes).context("not a valid wasm module or component")?;
    match declared {
        Some(d) if d != sniffed => {
            bail!("declared runtime {d:?} disagrees with the artifact ({sniffed:?})")
        }
        Some(d) => Ok(d),
        None => Ok(sniffed),
    }
}

/// Per-invocation host state for the component path. Implements `WasiView` (core WASI),
/// `WasiHttpView` (incoming + the *denied* outgoing handler), and holds the memory limiter.
struct HostState {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    table: ResourceTable,
    limits: StoreLimits,
}

impl IoView for HostState {
    fn table(&mut self) -> &mut ResourceTable {
        &mut self.table
    }
}

impl WasiView for HostState {
    fn ctx(&mut self) -> &mut WasiCtx {
        &mut self.wasi
    }
}

impl WasiHttpView for HostState {
    fn ctx(&mut self) -> &mut WasiHttpCtx {
        &mut self.http
    }

    /// **EGRESS OFF (P0).** Every outbound request from tenant code is denied here,
    /// before `default_send_request` (the only code that opens an outbound socket) can
    /// run. This is the structural chokepoint the threat model requires; the deferred
    /// host-mediated outbound-I/O arc will replace this with an allowlisted, SSRF-guarded
    /// policy. Returns a clean `wasi:http` error so the guest's `fetch` rejects gracefully.
    fn send_request(
        &mut self,
        _request: hyper::Request<HyperOutgoingBody>,
        _config: OutgoingRequestConfig,
    ) -> HttpResult<HostFutureIncomingResponse> {
        Err(ErrorCode::InternalError(Some(
            "outbound network is disabled for functions".to_string(),
        ))
        .into())
    }
}

impl HostState {
    fn new(env: &BTreeMap<String, String>) -> Self {
        let mut builder = WasiCtxBuilder::new();
        // No preopens, no stdio inheritance, no network — all denied explicitly so a
        // linked-but-unused capability still fails closed if a component reaches for it.
        builder
            .allow_tcp(false)
            .allow_udp(false)
            .allow_ip_name_lookup(false)
            .socket_addr_check(|_, _| Box::pin(async { false }));
        for (k, v) in env {
            builder.env(k, v);
        }
        Self {
            wasi: builder.build(),
            http: WasiHttpCtx::new(),
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(FUNCTION_MEMORY_MAX)
                .build(),
        }
    }
}

/// A loaded function, pre-compiled and ready to invoke. Both variants carry the
/// project-secret env to inject per invocation.
enum LoadedFunction {
    CoreModule {
        engine: Engine,
        module: Module,
        linker: Arc<Linker<WasiP1Ctx>>,
        env: BTreeMap<String, String>,
    },
    Component {
        pre: Arc<ProxyPre<HostState>>,
        env: BTreeMap<String, String>,
    },
}

pub struct FunctionRuntime {
    /// Sync engine for the legacy wasip1 path (fuel + epoch).
    sync_engine: Engine,
    /// Async engine for the component path (async + fuel + epoch).
    async_engine: Engine,
    functions: HashMap<String, Arc<LoadedFunction>>,
}

impl FunctionRuntime {
    pub fn new() -> Self {
        // Both engines get fuel + epoch interruption. A single detached ticker increments
        // both shared epoch counters, so a tight loop in either path is bounded even when
        // fuel is generous. Engine clones share epoch state (Arc-backed), so the loaded
        // functions' clones observe the same ticks.
        let sync_engine = {
            let mut cfg = Config::new();
            cfg.consume_fuel(true);
            cfg.epoch_interruption(true);
            Engine::new(&cfg).expect("sync engine config is valid")
        };
        let async_engine = {
            let mut cfg = Config::new();
            cfg.async_support(true);
            cfg.consume_fuel(true);
            cfg.epoch_interruption(true);
            Engine::new(&cfg).expect("async engine config is valid")
        };

        let se = sync_engine.clone();
        let ae = async_engine.clone();
        std::thread::Builder::new()
            .name("fn-epoch".to_string())
            .spawn(move || {
                loop {
                    std::thread::sleep(EPOCH_TICK);
                    se.increment_epoch();
                    ae.increment_epoch();
                }
            })
            .expect("spawn epoch ticker");

        Self {
            sync_engine,
            async_engine,
            functions: HashMap::new(),
        }
    }

    fn load_module(&mut self, name: &str, wasm_path: &Path) -> Result<()> {
        let bytes = std::fs::read(wasm_path)
            .with_context(|| format!("read function {}", wasm_path.display()))?;

        let sidecar = load_sidecar(wasm_path)?;
        let declared = sidecar
            .runtime
            .as_deref()
            .map(RuntimeKind::parse)
            .transpose()?;
        let kind = resolve_kind(declared, &bytes)?;
        let env = sidecar.env;

        let loaded = match kind {
            RuntimeKind::Wasip1 => {
                let module = Module::from_binary(&self.sync_engine, &bytes)
                    .with_context(|| format!("compile wasip1 module {}", wasm_path.display()))?;
                let mut linker = Linker::new(&self.sync_engine);
                preview1::add_to_linker_sync(&mut linker, |ctx| ctx)?;
                LoadedFunction::CoreModule {
                    engine: self.sync_engine.clone(),
                    module,
                    linker: Arc::new(linker),
                    env,
                }
            }
            RuntimeKind::WasiHttp => {
                let component = Component::from_binary(&self.async_engine, &bytes)
                    .with_context(|| format!("compile component {}", wasm_path.display()))?;
                let mut linker = ComponentLinker::new(&self.async_engine);
                // Full wasi p2 provides io/cli/clocks/random + `wasi:cli/environment`
                // (the channel project secrets ride in on). Then add ONLY the http
                // interfaces (types + outgoing-handler) to avoid double-defining wasi:io;
                // outgoing-handler routes through our denying `send_request`.
                wasmtime_wasi::p2::add_to_linker_async(&mut linker)?;
                wasmtime_wasi_http::add_only_http_to_linker_async(&mut linker)?;
                let pre =
                    ProxyPre::new(linker.instantiate_pre(&component)?).with_context(|| {
                        format!("pre-instantiate component {}", wasm_path.display())
                    })?;
                LoadedFunction::Component {
                    pre: Arc::new(pre),
                    env,
                }
            }
        };

        info!(name, path = %wasm_path.display(), runtime = ?kind, "loaded function");
        self.functions.insert(name.to_string(), Arc::new(loaded));
        Ok(())
    }

    pub fn load_all_from_dir(&mut self, dir: &Path) -> Result<()> {
        if !dir.exists() {
            return Ok(());
        }
        for entry in std::fs::read_dir(dir)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "wasm") {
                let name = path
                    .file_stem()
                    .and_then(|s| s.to_str())
                    .unwrap_or("unknown")
                    .to_string();
                // A single bad function is skipped + logged, never aborting agent boot or
                // poisoning its siblings.
                if let Err(e) = self.load_module(&name, &path) {
                    error!(function = %name, error = %e, "failed to load function (skipped)");
                }
            }
        }
        Ok(())
    }

    pub fn has_function(&self, name: &str) -> bool {
        self.functions.contains_key(name)
    }

    pub fn list_functions(&self) -> Vec<String> {
        self.functions.keys().cloned().collect()
    }

    /// Invoke a function. The wasip1 path runs sync on a blocking thread; the component
    /// path runs async on the agent's tokio runtime. Both are bounded by the kill-switch
    /// trio (fuel + epoch + outer wall-clock timeout).
    pub async fn invoke(&self, name: &str, req: FunctionRequest) -> Result<FunctionResponse> {
        let func = self
            .functions
            .get(name)
            .cloned()
            .ok_or_else(|| anyhow::anyhow!("function '{name}' not found"))?;

        match &*func {
            LoadedFunction::CoreModule { .. } => {
                let func = func.clone();
                let name = name.to_string();
                match tokio::task::spawn_blocking(move || invoke_wasip1(&func, &req)).await {
                    Ok(r) => r,
                    Err(e) => {
                        error!(function = %name, error = %e, "wasip1 task panicked");
                        Ok(FunctionResponse::error(500, "internal error"))
                    }
                }
            }
            LoadedFunction::Component { pre, env } => {
                match tokio::time::timeout(
                    FUNCTION_WALL_TIMEOUT,
                    invoke_component(pre.clone(), env.clone(), req),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => {
                        warn!(function = %name, "function timed out (wall-clock)");
                        Ok(FunctionResponse::error(504, "function timed out"))
                    }
                }
            }
        }
    }
}

impl Default for FunctionRuntime {
    fn default() -> Self {
        Self::new()
    }
}

/// Read the optional `_functions/{name}.json` sidecar sitting beside the `.wasm`.
fn load_sidecar(wasm_path: &Path) -> Result<FunctionSidecar> {
    let json_path = wasm_path.with_extension("json");
    match std::fs::read(&json_path) {
        Ok(bytes) => serde_json::from_slice(&bytes)
            .with_context(|| format!("parse sidecar {}", json_path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(FunctionSidecar::default()),
        Err(e) => Err(e).with_context(|| format!("read sidecar {}", json_path.display())),
    }
}

/// Legacy wasip1 invocation: JSON request on stdin, JSON response on stdout. Bounded by
/// fuel + the shared epoch deadline.
fn invoke_wasip1(func: &LoadedFunction, req: &FunctionRequest) -> Result<FunctionResponse> {
    let (engine, module, linker, env) = match func {
        LoadedFunction::CoreModule {
            engine,
            module,
            linker,
            env,
        } => (engine, module, linker, env),
        _ => unreachable!("invoke_wasip1 on a non-core function"),
    };

    let req_json = serde_json::to_vec(req)?;
    let stdin = MemoryInputPipe::new(Bytes::from(req_json));
    let stdout = MemoryOutputPipe::new(MAX_RESPONSE_BODY);
    let stderr = MemoryOutputPipe::new(64 * 1024);
    let stdout_clone = stdout.clone();
    let stderr_clone = stderr.clone();

    let mut builder = WasiCtxBuilder::new();
    builder
        .stdin(stdin)
        .stdout(stdout)
        .stderr(stderr)
        .allow_tcp(false)
        .allow_udp(false)
        .allow_ip_name_lookup(false)
        .socket_addr_check(|_, _| Box::pin(async { false }));
    for (k, v) in env {
        builder.env(k, v);
    }
    let wasi_ctx = builder.build_p1();

    let mut store = Store::new(engine, wasi_ctx);
    store.set_fuel(FUNCTION_FUEL)?;
    store.set_epoch_deadline(epoch_deadline_ticks());

    let instance = linker
        .instantiate(&mut store, module)
        .context("instantiate wasip1 module")?;
    let start = instance
        .get_typed_func::<(), ()>(&mut store, "_start")
        .context("function must export '_start'")?;
    let result = start.call(&mut store, ());
    drop(store);

    let output = stdout_clone.contents();
    let err_len = stderr_clone.contents().len();
    // Never log guest stderr *contents* — once project secrets are injected as env a
    // function that prints its environment would otherwise exfil them to the log shipper.
    info!(
        stdout_len = output.len(),
        stderr_len = err_len,
        "wasip1 function complete"
    );

    if let Err(e) = result {
        error!(error = %e, "wasip1 function execution failed");
        return Ok(FunctionResponse::error(500, "function error"));
    }
    if output.is_empty() {
        return Ok(FunctionResponse::error(500, "function produced no output"));
    }
    serde_json::from_slice(&output).context("function output is not a valid JSON response")
}

/// `wasi:http` component invocation. Synthesizes an `IncomingRequest` from the
/// `FunctionRequest`, runs the exported `incoming-handler`, and reads back the
/// `OutgoingResponse` under a size cap. Bounded by fuel + the shared epoch deadline; the
/// caller wraps this in the outer wall-clock timeout.
async fn invoke_component(
    pre: Arc<ProxyPre<HostState>>,
    env: BTreeMap<String, String>,
    req: FunctionRequest,
) -> Result<FunctionResponse> {
    let mut store = Store::new(pre.engine(), HostState::new(&env));
    store.set_fuel(FUNCTION_FUEL)?;
    store.set_epoch_deadline(epoch_deadline_ticks());
    store.limiter(|s| &mut s.limits);

    let hyper_req = build_incoming_request(&req)?;
    let incoming = store
        .data_mut()
        .new_incoming_request(Scheme::Http, hyper_req)
        .context("build incoming request resource")?;
    let (tx, rx) = tokio::sync::oneshot::channel();
    let outparam = store
        .data_mut()
        .new_response_outparam(tx)
        .context("build response outparam")?;

    // Run the handler on its own task so a streaming guest can make progress while we
    // read the response concurrently (and so we can drop it on timeout). The guest signals
    // the response via the outparam, which fires `rx`.
    let task = tokio::task::spawn(async move {
        let proxy = pre.instantiate_async(&mut store).await?;
        proxy
            .wasi_http_incoming_handler()
            .call_handle(store, incoming, outparam)
            .await?;
        Ok::<(), anyhow::Error>(())
    });

    let resp = match rx.await {
        Ok(Ok(resp)) => resp,
        Ok(Err(code)) => {
            warn!(error = %code, "function returned an error response");
            return Ok(FunctionResponse::error(502, "function error"));
        }
        // Sender dropped without setting a response: the guest returned (or trapped)
        // without calling `response-outparam::set`. Surface the task error if any.
        Err(_) => {
            let detail = match task.await {
                Ok(Ok(())) => "function produced no response".to_string(),
                Ok(Err(e)) => {
                    error!(error = %e, "function execution failed");
                    "function error".to_string()
                }
                Err(e) => {
                    error!(error = %e, "function task panicked");
                    "internal error".to_string()
                }
            };
            return Ok(FunctionResponse::error(500, &detail));
        }
    };

    let (parts, body) = resp.into_parts();
    let body = match Limited::new(body, MAX_RESPONSE_BODY).collect().await {
        Ok(c) => c.to_bytes().to_vec(),
        Err(_) => {
            warn!("function response body exceeded cap or failed to read");
            return Ok(FunctionResponse::error(502, "function response too large"));
        }
    };
    let headers = parts
        .headers
        .iter()
        .map(|(k, v)| {
            (
                k.to_string(),
                String::from_utf8_lossy(v.as_bytes()).to_string(),
            )
        })
        .collect();

    Ok(FunctionResponse {
        status: parts.status.as_u16(),
        headers,
        body,
    })
}

/// Build a `hyper::Request` (the shape `new_incoming_request` consumes — its body error
/// must be `hyper::Error`) from our `FunctionRequest`. The body is fully buffered already
/// (capped upstream in main.rs).
fn build_incoming_request(
    req: &FunctionRequest,
) -> Result<hyper::Request<BoxBody<Bytes, hyper::Error>>> {
    let path_and_query = if req.query.is_empty() {
        req.path.clone()
    } else {
        format!("{}?{}", req.path, req.query)
    };

    let mut builder = hyper::Request::builder()
        .method(req.method.as_str())
        .uri(path_and_query);
    let mut has_host = false;
    for (k, v) in &req.headers {
        if k.eq_ignore_ascii_case("host") {
            has_host = true;
        }
        builder = builder.header(k, v);
    }
    // `wasi:http` requires an authority; real requests carry a Host header, but inject a
    // fallback so a malformed request degrades cleanly instead of 500-ing the runtime.
    if !has_host {
        builder = builder.header("host", "localhost");
    }
    let body: BoxBody<Bytes, hyper::Error> = Full::new(Bytes::from(req.body.clone()))
        .map_err(|never| match never {})
        .boxed();
    builder.body(body).context("assemble incoming request")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn classifies_core_module_preamble() {
        // `\0asm` + version 1 (core module): 00 61 73 6d 01 00 00 00
        let bytes = [0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00];
        assert_eq!(classify_preamble(&bytes), Some(RuntimeKind::Wasip1));
    }

    #[test]
    fn classifies_component_preamble() {
        // `\0asm` + version 0x0d, layer 1 (component): 00 61 73 6d 0d 00 01 00
        let bytes = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        assert_eq!(classify_preamble(&bytes), Some(RuntimeKind::WasiHttp));
    }

    #[test]
    fn rejects_non_wasm() {
        assert_eq!(classify_preamble(b"not wasm at all"), None);
        assert_eq!(classify_preamble(&[0x00, 0x61]), None);
    }

    #[test]
    fn runtime_kind_is_a_closed_set() {
        assert_eq!(
            RuntimeKind::parse("wasi-http").unwrap(),
            RuntimeKind::WasiHttp
        );
        assert_eq!(RuntimeKind::parse("wasip1").unwrap(), RuntimeKind::Wasip1);
        assert!(RuntimeKind::parse("wasip2").is_err());
        assert!(RuntimeKind::parse("").is_err());
    }

    #[test]
    fn manifest_disagreeing_with_artifact_is_rejected() {
        let component = [0x00, 0x61, 0x73, 0x6d, 0x0d, 0x00, 0x01, 0x00];
        // Declares wasip1 but ships a component → reject.
        assert!(resolve_kind(Some(RuntimeKind::Wasip1), &component).is_err());
        // Agreement is accepted.
        assert_eq!(
            resolve_kind(Some(RuntimeKind::WasiHttp), &component).unwrap(),
            RuntimeKind::WasiHttp
        );
        // No manifest → sniff decides.
        assert_eq!(
            resolve_kind(None, &component).unwrap(),
            RuntimeKind::WasiHttp
        );
    }

    #[test]
    fn epoch_deadline_is_positive() {
        assert!(epoch_deadline_ticks() >= 1);
    }

    /// Path to the committed `wasi:http` component fixture (built from
    /// `templates/function-rust` with `cargo build --target wasm32-wasip2`).
    fn fixture() -> std::path::PathBuf {
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/echo-component.wasm")
    }

    /// A scratch copy of the fixture with an optional sidecar, so per-test classification
    /// + env can be exercised against a *real* component without mutating the shared one.
    fn staged(tag: &str, sidecar: Option<&str>) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("jkfn-{}-{}", tag, std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let wasm = dir.join("echo.wasm");
        std::fs::copy(fixture(), &wasm).unwrap();
        if let Some(json) = sidecar {
            std::fs::write(dir.join("echo.json"), json).unwrap();
        }
        wasm
    }

    /// The real component runs through the full wasmtime path and returns 200, AND its
    /// in-guest outbound `fetch` is denied by the host — proving the egress-off invariant
    /// structurally, not just by config.
    #[tokio::test]
    async fn component_executes_and_egress_is_denied() {
        let mut rt = FunctionRuntime::new();
        rt.load_module("echo", &fixture()).expect("load component");
        assert!(rt.has_function("echo"));

        let req = FunctionRequest {
            method: "GET".into(),
            path: "/hello".into(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        };
        let resp = rt.invoke("echo", req).await.expect("invoke");
        let text = String::from_utf8_lossy(&resp.body);
        assert_eq!(resp.status, 200, "body: {text}");
        assert!(
            text.contains("hello from a wasi:http component"),
            "got: {text}"
        );
        // The component issued a real outbound request; the host must have refused it.
        assert!(text.contains("egress=DENIED"), "egress not denied! got: {text}");
    }

    /// Project secrets injected via the sidecar env reach the component (pre-validates the
    /// secrets mechanism end-to-end through the real runtime).
    #[tokio::test]
    async fn component_reads_injected_env() {
        let wasm = staged("env", Some(r#"{"env":{"DEMO_SECRET":"hunter2"}}"#));
        let mut rt = FunctionRuntime::new();
        rt.load_module("echo", &wasm).expect("load component");

        let req = FunctionRequest {
            method: "GET".into(),
            path: "/".into(),
            query: String::new(),
            headers: vec![],
            body: vec![],
        };
        let resp = rt.invoke("echo", req).await.expect("invoke");
        let text = String::from_utf8_lossy(&resp.body);
        assert!(text.contains("DEMO_SECRET=hunter2"), "got: {text}");
        std::fs::remove_dir_all(wasm.parent().unwrap()).ok();
    }

    /// A sidecar that declares a runtime disagreeing with the real artifact is rejected at
    /// load (a tenant must not be able to declare one kind and ship another).
    #[test]
    fn real_component_with_mismatched_sidecar_is_rejected() {
        let wasm = staged("mismatch", Some(r#"{"runtime":"wasip1"}"#));
        let mut rt = FunctionRuntime::new();
        let err = rt.load_module("echo", &wasm).unwrap_err();
        assert!(err.to_string().contains("disagrees"), "got: {err}");
        std::fs::remove_dir_all(wasm.parent().unwrap()).ok();
    }
}
