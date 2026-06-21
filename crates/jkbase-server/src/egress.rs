//! Default-deny **egress proxy** for build VMs (design §9; threat-model P0-1).
//!
//! A build VM runs attacker-controlled code and may only reach the network
//! through this host-side forward proxy, which is itself the SSRF/exfil chokepoint
//! and so must be conservative. Two **independent, both-required** checks gate
//! every connection:
//!
//! 1. **Hostname allowlist** — only the curated registry/git hosts
//!    ([`DEFAULT_ALLOWLIST`]); exact match, never a tenant-supplied host.
//! 2. **Safe destination IP** — the proxy resolves the hostname *itself* and
//!    pins egress to a resolved **public** IP, rejecting RFC1918/loopback/
//!    link-local/cloud-metadata/CGNAT/etc. ([`ip_is_public`]). Resolving here
//!    (not in the guest) and connecting to the pinned IP defeats DNS-rebind/
//!    TOCTOU, and re-checking on *every* request/CONNECT defeats off-allowlist
//!    redirects (each hop the client follows is a fresh, independently-gated
//!    request through the proxy).
//!
//! This file is the allowlist + SSRF layer. On top of it, an optional TLS-terminating
//! caching **mirror** ([`crate::mirror`]) is attached to the narrow proxy only: for a
//! CONNECT to a package-registry host (and only those — [`host_is_mirrorable`]) the
//! proxy MITMs the connection to serve cross-tenant-deduped, content-verified
//! artifacts. Every other CONNECT — git-over-https, the dockerfile allow-any proxy,
//! anything else — stays a blind tunnel. The SSRF allowlist+pin gate runs FIRST,
//! unchanged, and the pinned address is the one the mirror dials (no re-resolve).

use anyhow::Result;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{debug, info, warn};

use crate::build_ca::host_is_mirrorable;
use crate::mirror::MirrorTls;

/// Max concurrent egress connections. Bounds task/FD use so a hostile build VM
/// can't slowloris the shared server process to FD exhaustion.
const MAX_CONNS: usize = 256;
/// A client must send its request head within this window (anti-slowloris).
const HEAD_TIMEOUT: Duration = Duration::from_secs(20);
/// Hard ceiling on a single connection's total lifetime, so a killed guest whose
/// socket never FINs can't pin a task/FD indefinitely.
const CONN_TIMEOUT: Duration = Duration::from_secs(600);

/// Curated egress allowlist: the dependency registries + git hosts a build may
/// fetch from, plus their known content-download hosts. Exact-match only.
pub const DEFAULT_ALLOWLIST: &[&str] = &[
    // Rust
    "crates.io",
    "static.crates.io",
    "index.crates.io",
    // Node
    "registry.npmjs.org",
    // Python
    "pypi.org",
    "files.pythonhosted.org",
    // Go: the module proxy + checksum DB the toolchain uses by default (GOPROXY +
    // GOSUMDB). The buildpack pins GOSUMDB=sum.golang.org and leaves GOPROXY at its
    // default for the fetch, forcing GOPROXY=off only for the offline compile.
    "proxy.golang.org",
    "sum.golang.org",
    // Git deps
    "github.com",
    "codeload.github.com",
    "objects.githubusercontent.com",
    "raw.githubusercontent.com",
    "gitlab.com",
];

/// Why an egress connection was refused (for logging; the client sees a 403/502).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Deny {
    /// Hostname not on the allowlist.
    HostNotAllowed,
    /// DNS resolution failed.
    ResolveFailed,
    /// The host resolved only to non-public (SSRF) addresses.
    NoSafeAddr,
}

// Public-IP / allowlist SSRF logic is the SINGLE source of truth in jkbase-common, so this
// build egress proxy and the function-runtime egress gate (jkbase-agent) apply byte-identical
// classification (P0-EGRESS-SHAREDLOGIC). Re-exported so existing call sites (incl.
// mirror.rs's `crate::egress::pick_safe_addr`) are unchanged.
pub use jkbase_common::egress::{host_allowed, pick_safe_addr};

/// Configuration for the egress proxy: the host allowlist and its mode.
pub struct EgressConfig {
    pub allowlist: Vec<String>,
    /// When true, bypass the hostname ALLOWLIST — any PUBLIC host on port 80/443
    /// is reachable. Used ONLY for the dedicated `builder = "dockerfile"` proxy,
    /// whose VMs run arbitrary `FROM`/`RUN` that need broad egress. The SSRF pin
    /// is NOT bypassed: `ip_is_public`/`pick_safe_addr` still reject private/
    /// metadata/link-local on every hop, the port stays 80/443-only, and the
    /// per-VM firewall still pins each VM to exactly this one proxy. The control
    /// plane's protection is the sealed VM + SSRF pin + firewall — never the
    /// allowlist — so widening to public-any does not weaken control-plane
    /// isolation, only the set of *public* hosts a sandboxed VM may reach.
    pub allow_any: bool,
    /// When set, CONNECTs to package-registry hosts ([`host_is_mirrorable`]) on 443
    /// are TLS-terminated and served from the shared content cache. ALWAYS `None` in
    /// `allow_any` mode — the dockerfile proxy never MITMs (invariant I-4). Everything
    /// not mirrorable stays a blind tunnel regardless.
    pub mirror: Option<Arc<MirrorTls>>,
}

impl EgressConfig {
    pub fn with_default_allowlist() -> Self {
        Self {
            allowlist: DEFAULT_ALLOWLIST.iter().map(|s| s.to_string()).collect(),
            allow_any: false,
            mirror: None,
        }
    }

    /// Public-any mode for the dockerfile-build proxy (allowlist bypassed, SSRF
    /// pin retained). See [`EgressConfig::allow_any`].
    pub fn allow_any_public() -> Self {
        Self {
            allowlist: Vec::new(),
            allow_any: true,
            mirror: None,
        }
    }

    /// Attach the package mirror (narrow proxy only). REFUSES to attach in allow_any
    /// mode (I-4): the dockerfile public-any proxy must never be able to TLS-terminate,
    /// so we drop the mirror here rather than rely solely on the `should_mirror` runtime
    /// gate — a defense-in-depth invariant that survives future refactors.
    pub fn with_mirror(mut self, mirror: Option<Arc<MirrorTls>>) -> Self {
        if self.allow_any && mirror.is_some() {
            tracing::error!("refusing to attach a mirror to an allow_any egress config (I-4)");
            self.mirror = None;
        } else {
            self.mirror = mirror;
        }
        self
    }
}

/// Allowlist the host (unless in public-any mode), resolve it *here*, and pin to a
/// safe public address. Returns the address to connect to, or a [`Deny`] reason.
async fn resolve_pinned(host: &str, port: u16, cfg: &EgressConfig) -> Result<SocketAddr, Deny> {
    // The allowlist is the ONLY thing public-any mode bypasses; everything below
    // (port restriction + SSRF address pin) applies unconditionally.
    if !cfg.allow_any && !host_allowed(host, &cfg.allowlist) {
        return Err(Deny::HostNotAllowed);
    }
    // Only the fetch protocols — never relay to SSH/SMTP/etc. on an allowed host.
    if port != 80 && port != 443 {
        return Err(Deny::HostNotAllowed);
    }
    // lookup_host handles both names and IP-literals; either way the result is
    // re-checked by pick_safe_addr, so an IP-literal host that somehow passed the
    // allowlist still can't reach a private/metadata address.
    let addrs = tokio::net::lookup_host((host, port))
        .await
        .map_err(|_| Deny::ResolveFailed)?;
    pick_safe_addr(addrs).ok_or(Deny::NoSafeAddr)
}

/// Whether a CONNECT should be TLS-terminated by the mirror rather than blind-tunneled.
/// The single source of truth for the MITM gate: a mirror must be attached, the proxy
/// must NOT be in allow_any mode (I-4), the port must be 443, and the host must be a
/// known package registry ([`host_is_mirrorable`]). Pure so it can be unit-tested.
fn should_mirror(cfg: &EgressConfig, host: &str, port: u16) -> bool {
    cfg.mirror.is_some() && !cfg.allow_any && port == 443 && host_is_mirrorable(host)
}

/// Serve the egress proxy on `listener` until the task is dropped. Each accepted
/// connection is handled independently.
pub async fn serve(listener: TcpListener, cfg: Arc<EgressConfig>) {
    // I-4 invariant: a TLS-terminating mirror is never armed on an allow_any proxy.
    debug_assert!(
        !(cfg.allow_any && cfg.mirror.is_some()),
        "I-4 violated: mirror attached to an allow_any egress config"
    );
    info!(allowlist = cfg.allowlist.len(), allow_any = cfg.allow_any, "egress proxy listening");
    let sem = Arc::new(Semaphore::new(MAX_CONNS));
    loop {
        let (client, peer) = match listener.accept().await {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "egress accept failed");
                continue;
            }
        };
        // Non-blocking cap: drop excess connections immediately rather than
        // queueing (which would just move the exhaustion to the accept backlog).
        let permit = match sem.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                debug!(%peer, "egress connection cap reached; dropping");
                drop(client);
                continue;
            }
        };
        let cfg = cfg.clone();
        tokio::spawn(async move {
            let _permit = permit;
            match tokio::time::timeout(CONN_TIMEOUT, handle_conn(client, cfg)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => debug!(%peer, error = %e, "egress connection ended"),
                Err(_) => debug!(%peer, "egress connection exceeded lifetime cap"),
            }
        });
    }
}

const MAX_HEAD_BYTES: usize = 16 * 1024;

/// Read the request head (up to the blank line) without consuming any body
/// bytes that follow. Bounded by [`MAX_HEAD_BYTES`].
async fn read_head(stream: &mut TcpStream) -> Result<Vec<u8>> {
    let mut buf = Vec::with_capacity(1024);
    let mut byte = [0u8; 1];
    loop {
        let n = stream.read(&mut byte).await?;
        if n == 0 {
            break;
        }
        buf.push(byte[0]);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
        if buf.len() > MAX_HEAD_BYTES {
            anyhow::bail!("request head exceeded {MAX_HEAD_BYTES} bytes");
        }
    }
    Ok(buf)
}

async fn deny_response(stream: &mut TcpStream, code: u16, reason: &str) -> Result<()> {
    let body = format!("egress denied: {reason}");
    let resp = format!(
        "HTTP/1.1 {code} {reason}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(resp.as_bytes()).await?;
    let _ = stream.flush().await;
    Ok(())
}

fn deny_code(d: Deny) -> (u16, &'static str) {
    match d {
        Deny::HostNotAllowed => (403, "Forbidden"),
        Deny::ResolveFailed => (502, "Bad Gateway"),
        Deny::NoSafeAddr => (403, "Forbidden"),
    }
}

async fn handle_conn(mut client: TcpStream, cfg: Arc<EgressConfig>) -> Result<()> {
    let head = match tokio::time::timeout(HEAD_TIMEOUT, read_head(&mut client)).await {
        Ok(r) => r?,
        Err(_) => anyhow::bail!("request head not received within {HEAD_TIMEOUT:?}"),
    };
    let head_str = String::from_utf8_lossy(&head);
    let request_line = head_str.lines().next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("");
    let target = parts.next().unwrap_or("");

    if method.eq_ignore_ascii_case("CONNECT") {
        // HTTPS tunnel: target is "host:port".
        let (host, port) = match split_authority(target, 443) {
            Some(hp) => hp,
            None => {
                deny_response(&mut client, 400, "Bad Request").await?;
                return Ok(());
            }
        };
        match resolve_pinned(&host, port, &cfg).await {
            Ok(addr) => {
                // MITM only for package registries on the narrow proxy (I-4). The SSRF
                // gate above already vetted+pinned `addr`; the mirror dials exactly it
                // (no re-resolve, I-5). Everything else is a blind tunnel.
                if should_mirror(&cfg, &host, port) {
                    let mirror = cfg
                        .mirror
                        .clone()
                        .expect("should_mirror() guarantees mirror is present");
                    client
                        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                        .await?;
                    info!(%host, %addr, "egress CONNECT mirror-MITM");
                    mirror.handle_mitm(client, host, addr).await;
                    return Ok(());
                }
                let mut upstream = TcpStream::connect(addr).await?;
                client
                    .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                    .await?;
                info!(%host, %addr, "egress CONNECT tunnel");
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            }
            Err(d) => {
                warn!(%host, ?d, "egress CONNECT denied");
                let (code, reason) = deny_code(d);
                deny_response(&mut client, code, reason).await?;
            }
        }
        return Ok(());
    }

    // Plaintext HTTP forward proxy: target is an absolute-form URI.
    let Some((host, port, path)) = parse_absolute_http(target) else {
        deny_response(&mut client, 400, "Bad Request").await?;
        return Ok(());
    };
    match resolve_pinned(&host, port, &cfg).await {
        Ok(addr) => {
            let mut upstream = TcpStream::connect(addr).await?;
            // Rewrite request-line to origin-form and forward the (rewritten) head.
            let rewritten = head_str.replacen(target, &path, 1);
            upstream.write_all(rewritten.as_bytes()).await?;
            info!(%host, %addr, "egress HTTP forward");
            // Stream request body + response; the client re-requests each redirect
            // through the proxy, so every hop is independently re-gated.
            let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
        }
        Err(d) => {
            warn!(%host, ?d, "egress HTTP denied");
            let (code, reason) = deny_code(d);
            deny_response(&mut client, code, reason).await?;
        }
    }
    Ok(())
}

/// Split `host:port` (or bare `host`) into `(host, port)`, defaulting the port.
/// Handles bracketed IPv6 literals (`[::1]:443`).
fn split_authority(authority: &str, default_port: u16) -> Option<(String, u16)> {
    if authority.is_empty() {
        return None;
    }
    if let Some(rest) = authority.strip_prefix('[') {
        // [ipv6]:port
        let (host, after) = rest.split_once(']')?;
        let port = after
            .strip_prefix(':')
            .and_then(|p| p.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_string(), port));
    }
    match authority.rsplit_once(':') {
        Some((h, p)) if !h.is_empty() => {
            let port = p.parse().ok()?;
            Some((h.to_string(), port))
        }
        _ => Some((authority.to_string(), default_port)),
    }
}

/// Parse an absolute-form HTTP request target (`http://host[:port]/path`) into
/// `(host, port, origin-form-path)`. Returns `None` for non-http schemes.
fn parse_absolute_http(target: &str) -> Option<(String, u16, String)> {
    let rest = target.strip_prefix("http://")?;
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    let (host, port) = split_authority(authority, 80)?;
    Some((host, port, path.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    // Test-only: the runtime path re-exports just host_allowed + pick_safe_addr; the
    // ip_is_public + IpAddr below are used only by these unit tests.
    use jkbase_common::egress::ip_is_public;
    use std::net::IpAddr;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    fn test_mirror(tag: &str) -> Arc<MirrorTls> {
        let _ = rustls::crypto::ring::default_provider().install_default();
        let dir = std::env::temp_dir().join(format!("jkb-egmir-{}-{tag}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let ca = crate::build_ca::BuildCa::load_or_generate(&dir).unwrap();
        let signer = Arc::new(crate::build_ca::CertSigner::new(ca));
        MirrorTls::new(&dir, signer, 1 << 30).unwrap()
    }

    #[test]
    fn mirror_gate_is_registry_443_narrow_only() {
        // Narrow proxy with a mirror: MITM exactly the registry hosts on 443.
        let narrow = EgressConfig::with_default_allowlist().with_mirror(Some(test_mirror("n")));
        assert!(should_mirror(&narrow, "registry.npmjs.org", 443));
        assert!(should_mirror(&narrow, "static.crates.io", 443));
        // Not a registry -> blind tunnel (git, etc.).
        assert!(!should_mirror(&narrow, "github.com", 443));
        // Wrong port -> never MITM.
        assert!(!should_mirror(&narrow, "registry.npmjs.org", 80));
        // No mirror attached -> blind tunnel.
        let plain = EgressConfig::with_default_allowlist();
        assert!(!should_mirror(&plain, "registry.npmjs.org", 443));
        // I-4: an allow_any (dockerfile) proxy NEVER MITMs. with_mirror DROPS the mirror
        // on an allow_any config (type-gate, not just the runtime should_mirror check).
        let any = EgressConfig::allow_any_public().with_mirror(Some(test_mirror("a")));
        assert!(any.mirror.is_none(), "with_mirror must refuse on allow_any (I-4)");
        assert!(!should_mirror(&any, "registry.npmjs.org", 443));
    }

    #[test]
    fn rejects_ssrf_addresses() {
        // Every one of these must be denied.
        for s in [
            "127.0.0.1",
            "127.10.20.30",
            "10.0.0.5",
            "172.16.0.1",
            "172.31.255.255",
            "192.168.1.1",
            "169.254.169.254", // cloud metadata
            "169.254.0.1",
            "0.0.0.0",
            "100.64.0.1",   // CGNAT
            "100.127.0.1",  // CGNAT
            "192.0.0.1",    // IETF
            "192.0.2.1",    // doc TEST-NET-1
            "198.18.0.1",   // benchmarking
            "198.51.100.1", // doc TEST-NET-2
            "203.0.113.1",  // doc TEST-NET-3
            "192.88.99.1",  // 6to4 relay
            "240.0.0.1",    // reserved
            "255.255.255.255",
            "224.0.0.1", // multicast
            "::1",
            "::",
            "fe80::1",                // link-local
            "fc00::1",                // ULA
            "fd12:3456::1",           // ULA
            "ff02::1",                // multicast
            "2001:db8::1",            // documentation
            "2002:c0a8:0101::1",      // 6to4
            "::ffff:169.254.169.254", // v4-mapped metadata
            "::ffff:10.0.0.1",        // v4-mapped private
        ] {
            assert!(!ip_is_public(ip(s)), "{s} must be denied");
        }
    }

    #[test]
    fn allows_real_public_addresses() {
        for s in [
            "1.1.1.1",
            "8.8.8.8",
            "140.82.112.3",        // github
            "151.101.0.1",         // fastly (crates/pypi CDN)
            "2606:4700:4700::1111", // cloudflare v6
            "2620:0:861:ed1a::1",  // public v6
        ] {
            assert!(ip_is_public(ip(s)), "{s} must be allowed");
        }
    }

    #[test]
    fn host_allowlist_is_exact() {
        let al: Vec<String> = DEFAULT_ALLOWLIST.iter().map(|s| s.to_string()).collect();
        assert!(host_allowed("crates.io", &al));
        assert!(host_allowed("CRATES.IO", &al)); // case-insensitive
        assert!(host_allowed("crates.io.", &al)); // trailing dot
        assert!(host_allowed("static.crates.io", &al));
        assert!(host_allowed("registry.npmjs.org", &al));
        // Spoofing / rebind hostnames must NOT pass.
        assert!(!host_allowed("crates.io.evil.com", &al));
        assert!(!host_allowed("evilcrates.io", &al));
        assert!(!host_allowed("notcrates.io", &al));
        assert!(!host_allowed("sub.crates.io", &al)); // exact only; not a known host
        assert!(!host_allowed("169.254.169.254", &al));
        assert!(!host_allowed("evil.com", &al));
    }

    #[test]
    fn pick_safe_addr_skips_unsafe() {
        let addrs = vec![
            "10.0.0.1:443".parse().unwrap(),          // private — skip
            "169.254.169.254:443".parse().unwrap(),   // metadata — skip
            "140.82.112.3:443".parse().unwrap(),      // public — take this
            "8.8.8.8:443".parse().unwrap(),
        ];
        let picked = pick_safe_addr(addrs).unwrap();
        assert_eq!(picked.ip(), ip("140.82.112.3"));

        // All-unsafe resolves to nothing (rebind attempt → denied).
        let unsafe_only: Vec<SocketAddr> = vec![
            "10.0.0.1:443".parse().unwrap(),
            "127.0.0.1:443".parse().unwrap(),
        ];
        assert!(pick_safe_addr(unsafe_only).is_none());
    }

    #[test]
    fn authority_parsing() {
        assert_eq!(split_authority("crates.io:443", 80), Some(("crates.io".into(), 443)));
        assert_eq!(split_authority("crates.io", 443), Some(("crates.io".into(), 443)));
        assert_eq!(split_authority("[::1]:8443", 443), Some(("::1".into(), 8443)));
        assert_eq!(split_authority("[2606:4700::1111]", 443), Some(("2606:4700::1111".into(), 443)));
        assert_eq!(split_authority("", 443), None);

        assert_eq!(
            parse_absolute_http("http://pypi.org/simple/flask/"),
            Some(("pypi.org".into(), 80, "/simple/flask/".into()))
        );
        assert_eq!(
            parse_absolute_http("http://registry.npmjs.org:8080/x"),
            Some(("registry.npmjs.org".into(), 8080, "/x".into()))
        );
        assert!(parse_absolute_http("https://crates.io/").is_none()); // not plaintext-forward
        assert!(parse_absolute_http("ftp://x/").is_none());
    }

    #[tokio::test]
    async fn resolve_pinned_denies_non_allowlisted_host_before_dns() {
        let cfg = EgressConfig::with_default_allowlist();
        // Not on the allowlist → denied without any DNS lookup.
        assert_eq!(
            resolve_pinned("evil.example.com", 443, &cfg).await,
            Err(Deny::HostNotAllowed)
        );
        assert_eq!(
            resolve_pinned("169.254.169.254", 443, &cfg).await,
            Err(Deny::HostNotAllowed)
        );
        // An allowed host on a non-fetch port (SSH/SMTP/...) is refused.
        assert_eq!(
            resolve_pinned("github.com", 22, &cfg).await,
            Err(Deny::HostNotAllowed)
        );
        assert_eq!(
            resolve_pinned("crates.io", 8080, &cfg).await,
            Err(Deny::HostNotAllowed)
        );
    }

    #[tokio::test]
    async fn resolve_pinned_allow_any_bypasses_allowlist_but_not_ssrf() {
        let cfg = EgressConfig::allow_any_public();
        // Public-any mode: an off-allowlist host is NOT HostNotAllowed (it gets to
        // DNS — here it resolves to a private/link-local literal, so the SSRF pin
        // still rejects it). The point: the allowlist no longer denies, but the
        // SSRF address pin and port restriction still hold.
        assert_eq!(
            resolve_pinned("169.254.169.254", 443, &cfg).await,
            Err(Deny::NoSafeAddr),
            "metadata IP must be rejected by the SSRF pin even in public-any mode"
        );
        assert_eq!(
            resolve_pinned("10.0.0.1", 80, &cfg).await,
            Err(Deny::NoSafeAddr),
            "private IP must be rejected by the SSRF pin"
        );
        // Non-fetch ports are still refused regardless of mode.
        assert_eq!(
            resolve_pinned("example.com", 22, &cfg).await,
            Err(Deny::HostNotAllowed),
            "non-80/443 port refused even in public-any mode"
        );
        // A public IP literal on a fetch port is allowed (no allowlist gate).
        assert_eq!(
            resolve_pinned("93.184.216.34", 443, &cfg).await,
            Ok("93.184.216.34:443".parse().unwrap()),
            "a public address is reachable in public-any mode"
        );
    }

    /// Live end-to-end: drive a real client (curl) through the proxy. Ignored by
    /// default (needs outbound internet). Run with `--ignored`.
    #[tokio::test]
    #[ignore = "needs outbound internet"]
    async fn proxy_tunnels_allowlisted_and_denies_others() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(serve(
            listener,
            Arc::new(EgressConfig::with_default_allowlist()),
        ));
        let proxy = format!("http://127.0.0.1:{port}");

        async fn curl(proxy: &str, url: &str) -> std::process::Output {
            tokio::process::Command::new("curl")
                .args(["-sS", "--max-time", "20", "-x", proxy, "-o", "/dev/null", url])
                .output()
                .await
                .unwrap()
        }

        // Allowlisted host: the CONNECT tunnel establishes and TLS completes
        // (any HTTP status is a successful transfer for curl without -f).
        let ok = curl(&proxy, "https://crates.io/").await;
        assert!(
            ok.status.success(),
            "allowlisted fetch should tunnel: {}",
            String::from_utf8_lossy(&ok.stderr)
        );

        // Off-allowlist host: the proxy 403s the CONNECT, so curl fails.
        let denied = curl(&proxy, "https://example.com/").await;
        assert!(!denied.status.success(), "off-allowlist host must be denied");
        let err = String::from_utf8_lossy(&denied.stderr);
        assert!(
            err.contains("403"),
            "expected a 403 proxy denial, got: {err}"
        );

        // A would-be SSRF to the cloud-metadata IP over plaintext HTTP: the proxy
        // returns its OWN 403 (it never connects to 169.254.169.254). curl exits 0
        // because it got a response, so assert the status code is the proxy denial.
        let meta = tokio::process::Command::new("curl")
            .args([
                "-sS",
                "--max-time",
                "10",
                "-x",
                &proxy,
                "-o",
                "/dev/null",
                "-w",
                "%{http_code}",
                "http://169.254.169.254/latest/meta-data/",
            ])
            .output()
            .await
            .unwrap();
        assert_eq!(
            String::from_utf8_lossy(&meta.stdout).trim(),
            "403",
            "metadata IP must get the proxy's 403, never be reached"
        );
    }
}
