//! The function egress gate — the single connect-time enforcement point for all
//! function outbound HTTP.
//!
//! A wasm component owns no kernel sockets, so 100% of a function's outbound traffic
//! funnels through one Rust call the guest cannot skip: [`WasiHttpView::send_request`]
//! (`function_runtime.rs`), which delegates here. This module resolves DNS through a
//! PINNED resolver, classifies every resolved IP into one of three zones, applies the
//! per-function public-egress policy, and connects to a single vetted, pinned address —
//! all on the guest's `eth0`/TAP, so the outbound also inherits the host netfilter fence.
//!
//! Load-bearing invariants (see docs/function-outbound-io-design.md §4):
//!   * P0-EGRESS-RESOLVER-PINNED — resolve via `172.16.0.1:53` programmatically, NEVER
//!     ambient `/etc/resolv.conf`; fail closed (no resolution ⇒ deny).
//!   * P0-EGRESS-POST-DNS / -PIN — classify resolved IPs per-address; dial only the vetted
//!     public IP; never re-resolve between vet and connect. IPv6 refused outright.
//!   * P0-EGRESS-ZONE-ORDER — zone classified BEFORE the policy switch: OWN-storage always
//!     allowed (survives sandbox); platform IPs + non-public always denied; only the public
//!     zone is modulated by the policy.
//!   * P0-EGRESS-PLATFORM-BY-IP — the platform's own public IP(s) are denied by pinned IP
//!     (host-asserted via `_platform.json`), defeating IP-literal / domain-fronting to
//!     `api.{domain}`.
//!   * P0-EGRESS-DUAL-ENFORCE — `vet_addr` runs at the selection site AND again at the
//!     connector immediately before `connect()`.
//!   * P0-EGRESS-NO-HOST-REDIRECT — a raw single-shot `hyper::client::conn::http1`
//!     connection never follows redirects; a 3xx returns verbatim and the guest must
//!     re-issue (re-entering this gate).
//!   * P0-EGRESS-HOST-AUTHORITY-COHERENT — the allowlist-checked name, the resolved name,
//!     the pinned IP's host, and the upstream `Host` are all the same; we re-derive `Host`
//!     from the vetted authority and never forward a divergent guest `Host`.
//!   * P0-EGRESS-ABORT — the connection worker (and its in-flight permit) is owned by the
//!     invocation; `task.abort()` on timeout tears down the FD and releases the permit.
//!   * P0-DOS-* — aggressive per-outbound timeouts, a SEPARATE in-flight semaphore, a
//!     per-invocation byte cap, and a per-VM (=per-project) connect-rate limiter.

use crate::log_sink::LogSink;
use anyhow::Result;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Frame, SizeHint};
use hyper::header::HOST;
use hyper_util::rt::TokioIo;
use jkbase_common::config::{PlatformEgress, ResolvedEgress};
use jkbase_common::egress::{host_allowed, ip_is_public};
use jkbase_common::logs::{EgressEvent, Verdict};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context as TaskContext, Poll};
use std::time::{Duration, Instant};
use tokio::net::TcpStream;
use tokio::sync::Semaphore;
use tokio::time::timeout;
use tracing::warn;
use wasmtime_wasi_http::bindings::http::types::{DnsErrorPayload, ErrorCode};
use wasmtime_wasi_http::body::{HyperIncomingBody, HyperOutgoingBody};
use wasmtime_wasi_http::types::{IncomingResponse, OutgoingRequestConfig};

/// The pinned DNS resolver: the runtime bridge gateway, where the host runs a forwarder
/// (`tools/setup-bridge.sh`). The ONLY resolver the agent ever consults — never the
/// ambient `/etc/resolv.conf` (P0-EGRESS-RESOLVER-PINNED). Mirrors the host's hardcoded
/// gateway (`gateway_ip: "172.16.0.1"`, jkbase-server).
const RESOLVER_IP: Ipv4Addr = Ipv4Addr::new(172, 16, 0, 1);
const RESOLVER_PORT: u16 = 53;

/// Separate, smaller-than-32 in-flight OUTBOUND permit pool, so a slowloris flood of
/// parked outbound calls cannot consume all of the per-VM invocation permits
/// (P0-DOS-OUTBOUND-TIMEOUTS). Held for the connection's lifetime; released on abort.
const MAX_INFLIGHT_OUTBOUND: usize = 16;

/// Aggressive per-outbound clamps, each `min()`'d against the caller's
/// `OutgoingRequestConfig` and all dwarfed by the 30s invocation wall clock. The
/// between-bytes (idle) clamp is the slowloris-body defense (P0-EGRESS-BUDGET-CLAMP).
const CONNECT_TIMEOUT_CAP: Duration = Duration::from_secs(5);
const FIRST_BYTE_TIMEOUT_CAP: Duration = Duration::from_secs(10);
const BETWEEN_BYTES_TIMEOUT_CAP: Duration = Duration::from_secs(10);

/// Per-invocation total outbound byte budget (request-out + response-in), independent of
/// the 10 MiB wasm response cap (P0-DOS-EGRESS-BYTE-CAP). Bounds a function looping an
/// upstream to push/pull gigabytes within one invocation before the lagging bandwidth
/// meter reacts.
const PER_INVOCATION_BYTE_CAP: u64 = 64 * 1024 * 1024;

/// Per-VM (= per-project — one VM per project) outbound connect-rate token bucket
/// (P0-DOS-CONNECT-STORM). Phase 1 has no keep-alive pool (every call is a fresh
/// connect+TLS), so this bounds the connect-storm + TLS-handshake CPU a looping function
/// inflicts on the agent (shared with the project's sites/servers).
const RATE_BURST: f64 = 60.0;
const RATE_REFILL_PER_SEC: f64 = 20.0;

/// Shared, process-wide egress context: the pinned resolver, the host-asserted platform
/// facts, a reusable TLS client config, and the per-VM DoS limiters. Built once at agent
/// boot; cloned (Arc) into every invocation's `HostState`.
pub struct EgressContext {
    resolver: hickory_resolver::TokioAsyncResolver,
    /// The OWN object-store host (normalized), if the host asserted one. A request to this
    /// EXACT host resolving to a platform IP is Zone-1 OWN-stuff — allowed under any policy.
    storage_host: Option<String>,
    /// The platform's own public IP(s) (host-asserted). Any resolved destination in this
    /// set is Zone-2 PLATFORM (deny) unless the request host is `storage_host`.
    platform_ips: HashSet<IpAddr>,
    tls: Arc<rustls::ClientConfig>,
    inflight: Arc<Semaphore>,
    rate: Mutex<TokenBucket>,
    /// The shared log sink — every egress decision is recorded into its reserved
    /// `stream == "egress"` channel (observe-by-default; P0-OBS-UNCONDITIONAL).
    log_sink: Arc<LogSink>,
}

impl EgressContext {
    /// Build the shared context from the host-asserted platform facts (`_platform.json`).
    /// A malformed `platform_ips` entry is dropped (logged), never treated as "allow".
    pub fn new(platform: &PlatformEgress, log_sink: Arc<LogSink>) -> Result<Arc<Self>> {
        let resolver = build_resolver();
        let tls = build_tls_config();
        let mut platform_ips = HashSet::new();
        for raw in &platform.platform_ips {
            match raw.parse::<IpAddr>() {
                Ok(ip) => {
                    platform_ips.insert(ip);
                }
                Err(_) => warn!(entry = %raw, "ignoring malformed platform_ips entry"),
            }
        }
        let storage_host = platform
            .storage_host
            .as_deref()
            .map(|h| h.trim_end_matches('.').to_ascii_lowercase())
            .filter(|h| !h.is_empty());
        Ok(Arc::new(Self {
            resolver,
            storage_host,
            platform_ips,
            tls,
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT_OUTBOUND)),
            rate: Mutex::new(TokenBucket::new(RATE_BURST, RATE_REFILL_PER_SEC)),
            log_sink,
        }))
    }

    /// The host-asserted platform storage host (e.g. `storage.jkbase.app`), if set. The
    /// own-bucket binding signs SigV4 for this host only.
    pub fn storage_host(&self) -> Option<&str> {
        self.storage_host.as_deref()
    }

    /// Issue a host-built HTTP/1.1 request to the OWN platform storage host over the Zone-1
    /// path and return `(status, response_body)` buffered. This is how the own-bucket binding
    /// reaches the object store: resolve `storage_host` via the PINNED resolver, REQUIRE the
    /// dialed IP to be a platform IP (P0-OBJ-PINNED-DEST — the agent can ONLY ever reach the
    /// platform storage ingress, never an attacker host, even if other config is wrong),
    /// connect pinned, TLS with SNI = the storage host (P0-EGRESS-TLS-E2E), send. `headers`
    /// are extra request headers (the SigV4 Authorization + x-amz-* the caller computed);
    /// `Host`, `content-length` are set here. The response body is capped at `MAX_RESPONSE_BODY`.
    pub async fn own_storage_request(
        &self,
        method: &str,
        path_and_query: &str,
        headers: &[(String, String)],
        body: Vec<u8>,
    ) -> Result<(u16, Vec<u8>), ErrorCode> {
        let host = self
            .storage_host
            .as_deref()
            .ok_or(ErrorCode::InternalError(None))?;
        // Resolve via the pinned resolver; the dial target MUST be a platform IP.
        let addrs: Vec<IpAddr> = match self.resolver.lookup_ip(host).await {
            Ok(l) => l.iter().filter(|ip| matches!(ip, IpAddr::V4(_))).collect(),
            Err(_) => Vec::new(),
        };
        let ip = addrs
            .into_iter()
            .find(|ip| self.platform_ips.contains(ip))
            .ok_or(ErrorCode::DestinationIpProhibited)?;
        let addr = SocketAddr::new(ip, 443);

        // Own-bucket traffic is per-VM (= per-project) egress like any other and MUST share
        // the one connect-storm budget (P0-DOS-CONNECT-STORM, review HIGH): phase 1 has no
        // keep-alive pool, so each call is a fresh connect+TLS — without this a function could
        // tight-loop store ops and storm the SHARED storage ingress + burn agent TLS-handshake
        // CPU, bypassing the rate gate `gate_send` enforces.
        if !self.rate.lock().expect("rate mutex").try_take() {
            return Err(ErrorCode::ConnectionLimitReached);
        }
        let _permit = self
            .inflight
            .clone()
            .try_acquire_owned()
            .map_err(|_| ErrorCode::ConnectionLimitReached)?;

        let tcp = timeout(CONNECT_TIMEOUT_CAP, TcpStream::connect(addr))
            .await
            .map_err(|_| ErrorCode::ConnectionTimeout)?
            .map_err(|_| ErrorCode::ConnectionRefused)?;
        let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
            .map_err(|_| ErrorCode::InternalError(None))?
            .to_owned();
        let connector = tokio_rustls::TlsConnector::from(self.tls.clone());
        let tls = timeout(CONNECT_TIMEOUT_CAP, connector.connect(server_name, tcp))
            .await
            .map_err(|_| ErrorCode::ConnectionTimeout)?
            .map_err(|_| ErrorCode::TlsProtocolError)?;
        let (mut sender, conn) = timeout(
            CONNECT_TIMEOUT_CAP,
            hyper::client::conn::http1::handshake(TokioIo::new(tls)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::HttpProtocolError)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            let _permit = _permit;
            let _ = conn.await;
        });

        let mut builder = hyper::Request::builder()
            .method(method)
            .uri(path_and_query)
            .header(HOST, host)
            .header("content-length", body.len());
        for (k, v) in headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let req = builder
            .body(Full::new(Bytes::from(body)))
            .map_err(|_| ErrorCode::InternalError(None))?;

        let resp = timeout(FIRST_BYTE_TIMEOUT_CAP, sender.send_request(req))
            .await
            .map_err(|_| ErrorCode::ConnectionReadTimeout)?
            .map_err(|_| ErrorCode::HttpProtocolError)?;
        let status = resp.status().as_u16();
        let body = Limited::new(resp.into_body(), MAX_OWN_STORAGE_BODY)
            .collect()
            .await
            .map_err(|_| ErrorCode::HttpProtocolError)?
            .to_bytes()
            .to_vec();
        worker.abort();
        Ok((status, body))
    }
}

/// Cap on a buffered own-bucket response body (matches the function response ceiling).
const MAX_OWN_STORAGE_BODY: usize = 10 * 1024 * 1024;

/// Record one egress decision into the reserved `stream == "egress"` channel (host-only,
/// coalesced; P0-OBS-UNCONDITIONAL / -STREAM-RESERVED). Metadata only — see [`EgressEvent`].
async fn emit(
    ctx: &EgressContext,
    function: &str,
    host: &str,
    port: u16,
    method: &str,
    verdict: Verdict,
    dest_ip: Option<String>,
) {
    ctx.log_sink
        .push_egress(EgressEvent {
            function: function.to_string(),
            dest_host: host.to_string(),
            dest_port: port,
            dest_ip,
            verdict,
            method: method.to_string(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            status: None,
        })
        .await;
}

/// Build the pinned resolver: ONLY `172.16.0.1:53`, IPv4-only (we refuse v6 anyway),
/// never reading the system config — so a misconfigured guest rootfs fails closed (no
/// resolution → deny) rather than falling back to ambient resolution.
fn build_resolver() -> hickory_resolver::TokioAsyncResolver {
    use hickory_resolver::config::{
        LookupIpStrategy, NameServerConfigGroup, ResolverConfig, ResolverOpts,
    };
    let ns = NameServerConfigGroup::from_ips_clear(&[IpAddr::V4(RESOLVER_IP)], RESOLVER_PORT, true);
    let config = ResolverConfig::from_parts(None, vec![], ns);
    let mut opts = ResolverOpts::default();
    opts.ip_strategy = LookupIpStrategy::Ipv4Only;
    // Bound a stalled lookup so a parked DNS query can't hold an invocation toward the 30s
    // wall clock (the local forwarder answers in ms when healthy). Single attempt — the one
    // forwarder either answers or it doesn't.
    opts.timeout = Duration::from_secs(2);
    opts.attempts = 1;
    hickory_resolver::TokioAsyncResolver::tokio(config, opts)
}

/// One reusable rustls client config (public webpki roots; no client auth). The agent
/// builds outbound TLS inside the tenant VM, so the host sees only ciphertext leaving the
/// TAP (P0-EGRESS-TLS-E2E).
fn build_tls_config() -> Arc<rustls::ClientConfig> {
    let roots = rustls::RootCertStore {
        roots: webpki_roots::TLS_SERVER_ROOTS.into(),
    };
    // Pin the `ring` provider EXPLICITLY rather than relying on the process-global default:
    // other workspace crates pull `aws-lc-rs` into the dependency graph, so `builder()`'s
    // auto-detection is ambiguous and panics. `builder_with_provider` is deterministic.
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    Arc::new(
        rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .expect("ring provider supports the default TLS versions")
            .with_root_certificates(roots)
            .with_no_client_auth(),
    )
}

/// A simple monotonic token bucket. `Instant`-based; the agent (a normal binary) may use
/// the wall/monotonic clock freely.
struct TokenBucket {
    tokens: f64,
    capacity: f64,
    refill_per_sec: f64,
    last: Instant,
}

impl TokenBucket {
    fn new(capacity: f64, refill_per_sec: f64) -> Self {
        Self::new_at(capacity, refill_per_sec, Instant::now())
    }

    fn try_take(&mut self) -> bool {
        self.try_take_at(Instant::now())
    }

    /// Clock-injecting variants. Production reads `Instant::now()` (above); tests drive `now`
    /// explicitly so refill is exact and never races scheduler jitter (the old wall-clock test
    /// flaked CI: ~1ms between takes refilled a token before the "exhausted" assert).
    fn new_at(capacity: f64, refill_per_sec: f64, now: Instant) -> Self {
        Self {
            tokens: capacity,
            capacity,
            refill_per_sec,
            last: now,
        }
    }

    fn try_take_at(&mut self, now: Instant) -> bool {
        let elapsed = now.duration_since(self.last).as_secs_f64();
        self.last = now;
        self.tokens = (self.tokens + elapsed * self.refill_per_sec).min(self.capacity);
        if self.tokens >= 1.0 {
            self.tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

/// The egress decision: which vetted address to dial, or a typed deny with the manifest
/// verdict that classifies WHY (so the observe record distinguishes sandbox vs allowlist vs
/// the hard platform fence, which share an `ErrorCode`).
enum Decision {
    /// Dial exactly this address (already vetted: public + policy-allowed, or OWN).
    Dial(SocketAddr),
    Deny(ErrorCode, Verdict),
}

/// Is `ip` a legitimate Zone-3 PUBLIC destination for a function? Fail-closed superset of
/// the netfilter fence: refuse IPv6 outright (phase 1 is IPv4-only egress), refuse the
/// platform's own public IP(s) (Zone-2 PLATFORM), and require `ip_is_public` (which already
/// excludes RFC1918 / CGNAT / link-local / metadata / ULA). This is the connector-site
/// re-check too (P0-EGRESS-DUAL-ENFORCE).
fn vet_public(ip: IpAddr, platform_ips: &HashSet<IpAddr>) -> bool {
    matches!(ip, IpAddr::V4(_)) && !platform_ips.contains(&ip) && ip_is_public(ip)
}

/// Classify the resolved addresses + host against the platform facts and the per-function
/// policy, returning the single address to dial or a typed deny. PURE (no I/O) so it is
/// unit-tested directly. Zone is decided BEFORE the policy switch (P0-EGRESS-ZONE-ORDER).
fn decide(
    addrs: &[IpAddr],
    host: &str,
    port: u16,
    storage_host: Option<&str>,
    platform_ips: &HashSet<IpAddr>,
    policy: &ResolvedEgress,
) -> Decision {
    let host_norm = host.trim_end_matches('.').to_ascii_lowercase();

    // Zone 1 — OWN object-store: the EXACT host the host asserted, resolving to a platform
    // ingress IP. Allowed regardless of policy (survives sandbox). The IP must be in the
    // platform set: a name match alone would fail open if a tenant ever controlled DNS for
    // a look-alike host (P0-EGRESS-OWN-HOST-ASSERTED).
    if let Some(storage) = storage_host
        && host_norm == storage
    {
        return match addrs
            .iter()
            .copied()
            .find(|ip| matches!(ip, IpAddr::V4(_)) && platform_ips.contains(ip))
        {
            Some(ip) => Decision::Dial(SocketAddr::new(ip, port)),
            None => Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform),
        };
    }

    // Zone 2 vs Zone 3 — pick the first PUBLIC, non-platform, IPv4 address. If none exists,
    // every resolved address is internal/platform/IPv6 ⇒ Zone-2 DENY, independent of policy.
    let Some(public_addr) = addrs
        .iter()
        .copied()
        .find(|ip| vet_public(*ip, platform_ips))
    else {
        return Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform);
    };

    // Zone 3 — PUBLIC: modulate by the per-function policy.
    match policy {
        ResolvedEgress::Default => Decision::Dial(SocketAddr::new(public_addr, port)),
        ResolvedEgress::Sandbox => {
            Decision::Deny(ErrorCode::HttpRequestDenied, Verdict::DenySandbox)
        }
        ResolvedEgress::Allowlist(hosts) => {
            if host_allowed(&host_norm, hosts) {
                Decision::Dial(SocketAddr::new(public_addr, port))
            } else {
                Decision::Deny(ErrorCode::HttpRequestDenied, Verdict::DenyAllowlist)
            }
        }
    }
}

/// Extract `(host, port)` from a request URI's authority, defaulting the port by scheme.
/// `None` ⇒ no usable authority.
fn authority_parts(uri: &hyper::Uri, use_tls: bool) -> Option<(String, u16)> {
    let auth = uri.authority()?;
    let host = auth.host().to_string();
    let port = auth.port_u16().unwrap_or(if use_tls { 443 } else { 80 });
    Some((host, port))
}

/// The async egress handler: resolve (pinned) → classify → connect (pinned) → handshake →
/// send, returning the wasi-http `IncomingResponse` the runtime drives. This is the body
/// `WasiHttpView::send_request` spawns onto the invocation's task tree (so abort tears it
/// down). On any deny it returns a typed `ErrorCode` and opens NO socket.
pub async fn gate_send(
    mut request: hyper::Request<HyperOutgoingBody>,
    config: OutgoingRequestConfig,
    ctx: Arc<EgressContext>,
    policy: ResolvedEgress,
    function: String,
) -> Result<IncomingResponse, ErrorCode> {
    let use_tls = config.use_tls;
    let method = request.method().to_string();
    let (host, port) =
        authority_parts(request.uri(), use_tls).ok_or(ErrorCode::HttpRequestUriInvalid)?;

    // Refuse IPv6 literals up front (phase 1 is IPv4-only egress — one rule removes a whole
    // class of v6-classifier-edge risk). An IPv6 destination is the hard fence.
    if host.parse::<std::net::Ipv6Addr>().is_ok() || host.contains(':') {
        emit(
            &ctx,
            &function,
            &host,
            port,
            &method,
            Verdict::DenyPlatform,
            None,
        )
        .await;
        return Err(ErrorCode::DestinationIpProhibited);
    }

    // Resolve via the PINNED resolver (or use a v4 literal directly). Fail closed on empty.
    let addrs: Vec<IpAddr> = if let Ok(v4) = host.parse::<Ipv4Addr>() {
        vec![IpAddr::V4(v4)]
    } else {
        match ctx.resolver.lookup_ip(host.as_str()).await {
            Ok(lookup) => lookup
                .iter()
                .filter(|ip| matches!(ip, IpAddr::V4(_)))
                .collect(),
            Err(_) => Vec::new(),
        }
    };
    if addrs.is_empty() {
        emit(&ctx, &function, &host, port, &method, Verdict::Error, None).await;
        return Err(ErrorCode::DnsError(DnsErrorPayload {
            rcode: None,
            info_code: None,
        }));
    }
    // The first resolved address — recorded on a deny so the manifest shows what the name
    // pointed at (IR primitive), even though we never dial it.
    let first_ip = addrs.first().map(|ip| ip.to_string());

    let addr = match decide(
        &addrs,
        &host,
        port,
        ctx.storage_host.as_deref(),
        &ctx.platform_ips,
        &policy,
    ) {
        Decision::Dial(a) => a,
        Decision::Deny(code, verdict) => {
            emit(&ctx, &function, &host, port, &method, verdict, first_ip).await;
            return Err(code);
        }
    };

    // Per-VM outbound connect-rate limiter (after the verdict, before any socket).
    if !ctx.rate.lock().expect("rate mutex").try_take() {
        emit(
            &ctx,
            &function,
            &host,
            port,
            &method,
            Verdict::Error,
            first_ip,
        )
        .await;
        return Err(ErrorCode::ConnectionLimitReached);
    }

    // Separate in-flight OUTBOUND permit — fail fast (don't park an invocation permit
    // waiting on a full outbound pool). Held by the connection worker until it ends.
    let permit = match ctx.inflight.clone().try_acquire_owned() {
        Ok(p) => p,
        Err(_) => {
            emit(
                &ctx,
                &function,
                &host,
                port,
                &method,
                Verdict::Error,
                first_ip,
            )
            .await;
            return Err(ErrorCode::ConnectionLimitReached);
        }
    };

    // Connector-site re-check (P0-EGRESS-DUAL-ENFORCE): the address we are about to dial
    // must still be a vetted public IP OR the OWN-storage platform IP — a policy-site bug
    // cannot slip an internal address past here.
    let own_ok = ctx
        .storage_host
        .as_deref()
        .is_some_and(|s| host.trim_end_matches('.').eq_ignore_ascii_case(s))
        && ctx.platform_ips.contains(&addr.ip());
    if !own_ok && !vet_public(addr.ip(), &ctx.platform_ips) {
        emit(
            &ctx,
            &function,
            &host,
            port,
            &method,
            Verdict::DenyPlatform,
            Some(addr.ip().to_string()),
        )
        .await;
        return Err(ErrorCode::DestinationIpProhibited);
    }

    // ALLOW: record the contact (host:port, pinned IP) BEFORE the connect, so an abort /
    // connect failure can lose the byte refinement but never the existence of the
    // destination (P0-OBS-UNCONDITIONAL).
    emit(
        &ctx,
        &function,
        &host,
        port,
        &method,
        Verdict::Allow,
        Some(addr.ip().to_string()),
    )
    .await;

    let connect_to = min_dur(config.connect_timeout, CONNECT_TIMEOUT_CAP);
    let first_byte = min_dur(config.first_byte_timeout, FIRST_BYTE_TIMEOUT_CAP);
    let between_bytes = min_dur(config.between_bytes_timeout, BETWEEN_BYTES_TIMEOUT_CAP);

    // Dial the EXACT pinned address — never the hostname, so there is no second resolution
    // to rebind (P0-EGRESS-PIN).
    let tcp = timeout(connect_to, TcpStream::connect(addr))
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::ConnectionRefused)?;

    // Shared request-out + response-in byte budget for this invocation.
    let budget = Arc::new(AtomicU64::new(PER_INVOCATION_BYTE_CAP));

    // HTTP/1.1 over (optionally) TLS. A single-shot connection: it cannot follow redirects
    // (P0-EGRESS-NO-HOST-REDIRECT).
    let (mut sender, worker) = if use_tls {
        let server_name = rustls::pki_types::ServerName::try_from(host.clone())
            .map_err(|_| {
                ErrorCode::DnsError(DnsErrorPayload {
                    rcode: None,
                    info_code: None,
                })
            })?
            .to_owned();
        let connector = tokio_rustls::TlsConnector::from(ctx.tls.clone());
        let tls_stream = timeout(connect_to, connector.connect(server_name, tcp))
            .await
            .map_err(|_| ErrorCode::ConnectionTimeout)?
            .map_err(|_| ErrorCode::TlsProtocolError)?;
        let (sender, conn) = timeout(
            connect_to,
            hyper::client::conn::http1::handshake(TokioIo::new(tls_stream)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::HttpProtocolError)?;
        // The connection worker OWNS the in-flight permit; abort/drop releases it and tears
        // down the FD (P0-EGRESS-ABORT).
        let worker = wasmtime_wasi::runtime::spawn(async move {
            let _permit = permit;
            let _ = conn.await;
        });
        (sender, worker)
    } else {
        let (sender, conn) = timeout(
            connect_to,
            hyper::client::conn::http1::handshake(TokioIo::new(tcp)),
        )
        .await
        .map_err(|_| ErrorCode::ConnectionTimeout)?
        .map_err(|_| ErrorCode::HttpProtocolError)?;
        let worker = wasmtime_wasi::runtime::spawn(async move {
            let _permit = permit;
            let _ = conn.await;
        });
        (sender, worker)
    };

    // Re-derive the upstream Host from the VETTED authority and overwrite any guest-set Host
    // (P0-EGRESS-HOST-AUTHORITY-COHERENT), then normalize the URI to path+query for the
    // single-connection send (http1 carries authority in Host, not the request line).
    let authority = if (use_tls && port == 443) || (!use_tls && port == 80) {
        host.clone()
    } else {
        format!("{host}:{port}")
    };
    if let Ok(hv) = hyper::header::HeaderValue::from_str(&authority) {
        request.headers_mut().insert(HOST, hv);
    }
    *request.uri_mut() = hyper::Uri::builder()
        .path_and_query(
            request
                .uri()
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/"),
        )
        .build()
        .map_err(|_| ErrorCode::HttpRequestUriInvalid)?;

    // Cap the OUTGOING body against the shared budget before sending.
    let (parts, out_body) = request.into_parts();
    let capped_out = CappedBody::new(out_body, budget.clone()).boxed();
    let request = hyper::Request::from_parts(parts, capped_out);

    let resp = timeout(first_byte, sender.send_request(request))
        .await
        .map_err(|_| ErrorCode::ConnectionReadTimeout)?
        .map_err(|_| ErrorCode::HttpProtocolError)?;

    // Map the hyper response body to the wasi-http body type, then cap the INCOMING body
    // against the same budget.
    let resp = resp.map(|body| {
        let mapped: HyperIncomingBody = body.map_err(|_| ErrorCode::HttpProtocolError).boxed();
        CappedBody::new(mapped, budget.clone()).boxed()
    });

    Ok(IncomingResponse {
        resp,
        worker: Some(worker),
        between_bytes_timeout: between_bytes,
    })
}

fn min_dur(a: Duration, b: Duration) -> Duration {
    if a < b { a } else { b }
}

/// A body that debits each data frame's length from a shared budget, erroring once the
/// budget is exhausted. Wraps both the request-out and response-in bodies so one
/// invocation cannot move more than [`PER_INVOCATION_BYTE_CAP`] total.
struct CappedBody<B> {
    inner: B,
    budget: Arc<AtomicU64>,
}

impl<B> CappedBody<B> {
    fn new(inner: B, budget: Arc<AtomicU64>) -> Self {
        Self { inner, budget }
    }
}

impl<B> Body for CappedBody<B>
where
    B: Body<Data = Bytes, Error = ErrorCode> + Unpin,
{
    type Data = Bytes;
    type Error = ErrorCode;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut TaskContext<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, ErrorCode>>> {
        match Pin::new(&mut self.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    let len = data.len() as u64;
                    // fetch_update: succeed only if the budget covers this frame.
                    let ok = self
                        .budget
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |b| b.checked_sub(len))
                        .is_ok();
                    if !ok {
                        return Poll::Ready(Some(Err(ErrorCode::InternalError(Some(
                            "egress byte budget exceeded".to_string(),
                        )))));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn platform(ips: &[&str]) -> HashSet<IpAddr> {
        ips.iter().map(|s| ip(s)).collect()
    }

    #[test]
    fn default_allows_public_denies_internal_and_platform() {
        let plat = platform(&["203.0.113.10"]);
        // Public host → dial the public addr.
        assert!(matches!(
            decide(&[ip("140.82.112.3")], "api.example.com", 443, None, &plat, &ResolvedEgress::Default),
            Decision::Dial(a) if a.ip() == ip("140.82.112.3")
        ));
        // Resolves to RFC1918 → Zone-2 deny even under Default.
        assert!(matches!(
            decide(
                &[ip("10.0.0.5")],
                "evil.example.com",
                443,
                None,
                &plat,
                &ResolvedEgress::Default
            ),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
        // Resolves to the platform's own public IP (domain-front to api.) → Zone-2 deny.
        assert!(matches!(
            decide(
                &[ip("203.0.113.10")],
                "api.attacker.com",
                443,
                None,
                &plat,
                &ResolvedEgress::Default
            ),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
        // Metadata IP literal → deny.
        assert!(matches!(
            decide(
                &[ip("169.254.169.254")],
                "169.254.169.254",
                80,
                None,
                &plat,
                &ResolvedEgress::Default
            ),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
    }

    #[test]
    fn mixed_rrset_pins_the_public_addr_and_skips_internal() {
        let plat = platform(&[]);
        // A public name resolving to [internal, public] dials only the public one.
        match decide(
            &[ip("10.0.0.1"), ip("140.82.112.3")],
            "cdn.example.com",
            443,
            None,
            &plat,
            &ResolvedEgress::Default,
        ) {
            Decision::Dial(a) => assert_eq!(a.ip(), ip("140.82.112.3")),
            Decision::Deny(..) => panic!("should dial the public addr"),
        }
    }

    #[test]
    fn ipv6_addr_is_refused() {
        let plat = platform(&[]);
        // An AAAA-only result (we filter v6 before decide, but defense in depth) → deny.
        assert!(matches!(
            decide(
                &[ip("2606:4700::1111")],
                "v6.example.com",
                443,
                None,
                &plat,
                &ResolvedEgress::Default
            ),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
    }

    #[test]
    fn sandbox_denies_public_but_allows_own_storage() {
        let plat = platform(&["203.0.113.10"]);
        let storage = Some("storage.jkbase.app");
        // Sandbox → public denied.
        assert!(matches!(
            decide(
                &[ip("140.82.112.3")],
                "api.stripe.com",
                443,
                storage,
                &plat,
                &ResolvedEgress::Sandbox
            ),
            Decision::Deny(ErrorCode::HttpRequestDenied, _)
        ));
        // OWN storage (host==storage, IP∈platform) → allowed EVEN under sandbox.
        assert!(matches!(
            decide(&[ip("203.0.113.10")], "storage.jkbase.app", 443, storage, &plat, &ResolvedEgress::Sandbox),
            Decision::Dial(a) if a.ip() == ip("203.0.113.10")
        ));
        // A look-alike storage host that does NOT resolve to a platform IP → deny (a name
        // match alone never suffices).
        assert!(matches!(
            decide(
                &[ip("140.82.112.3")],
                "storage.jkbase.app",
                443,
                storage,
                &plat,
                &ResolvedEgress::Sandbox
            ),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
    }

    #[test]
    fn allowlist_is_exact_and_does_not_override_the_fence() {
        let plat = platform(&[]);
        let al = ResolvedEgress::Allowlist(vec!["api.stripe.com".to_string()]);
        // Exact allowlisted public host → allowed.
        assert!(matches!(
            decide(
                &[ip("140.82.112.3")],
                "api.stripe.com",
                443,
                None,
                &plat,
                &al
            ),
            Decision::Dial(_)
        ));
        // Not on the list → denied.
        assert!(matches!(
            decide(&[ip("140.82.112.3")], "evil.com", 443, None, &plat, &al),
            Decision::Deny(ErrorCode::HttpRequestDenied, _)
        ));
        // On the list but resolves internal → STILL denied (allowlist widens public; it
        // never overrides the fence). Zone-2 deny precedes the policy.
        assert!(matches!(
            decide(&[ip("10.0.0.1")], "api.stripe.com", 443, None, &plat, &al),
            Decision::Deny(ErrorCode::DestinationIpProhibited, Verdict::DenyPlatform)
        ));
    }

    #[test]
    fn token_bucket_limits_then_refills() {
        // Deterministic clock: no time advances across the burst, so refill is exactly zero and
        // the bucket empties at precisely `capacity` takes (no wall-clock dependence / no sleep).
        let t0 = Instant::now();
        let mut tb = TokenBucket::new_at(2.0, 1000.0, t0);
        assert!(tb.try_take_at(t0));
        assert!(tb.try_take_at(t0));
        assert!(!tb.try_take_at(t0), "burst exhausted");
        // +5ms at 1000/s → 5 tokens refilled.
        assert!(
            tb.try_take_at(t0 + Duration::from_millis(5)),
            "refilled after a tick"
        );
    }
}
