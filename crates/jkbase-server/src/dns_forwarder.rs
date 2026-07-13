//! Host DNS forwarder for runtime VMs — the process that answers guest `/etc/resolv.conf`.
//!
//! Every runtime guest points its resolver at the bridge gateway `172.16.0.1:53`
//! (`container_supervisor::RUNTIME_RESOLV_CONF` for server apps; `function_egress::RESOLVER_IP`
//! for functions). This is the host side of that contract: it accepts a guest's DNS query on
//! `172.16.0.1:53` (UDP + TCP), relays it VERBATIM to the host's own resolver (whatever
//! `/etc/resolv.conf` lists — e.g. systemd-resolved's `127.0.0.53`), and relays the answer back.
//!
//! It REPLACES systemd-resolved's `DNSStubListenerExtra=172.16.0.1` — `tools/setup-bridge.sh` now
//! removes that drop-in and restarts resolved to hand the port off — so guest DNS is jkbase-owned:
//! bound to this process's lifecycle (no boot-order race where resolved bound `:53` before the
//! bridge existed), per-guest rate-limited, logged, and attributable to a project by source IP.
//!
//! ## Why forward to the host resolver rather than a public one
//! Many hosts (OVH, the prod target) block outbound UDP/53 to public resolvers, so a guest can't
//! use `1.1.1.1` directly and neither can we. The host's own resolver already reaches upstream
//! however that host can (systemd-resolved via DoT / the provider's resolvers), so we delegate to
//! it — provider-agnostic, and it inherits the host's known-good path. Upstream is discovered from
//! `/etc/resolv.conf`, floored to `127.0.0.53:53`, and never our own bind IP (loop guard).
//!
//! ## Threat model — NOT a containment boundary
//! Runtime server-app egress is already OPEN NAT (`setup-bridge.sh`: MASQUERADE + `FORWARD ACCEPT`;
//! only cloud-metadata/link-local + IPv6 are dropped). A hostile tenant can reach any public IP by
//! literal address or run its own in-guest resolver regardless of this forwarder — so a DNS
//! *allowlist* here would fence nothing it can't route around. The forwarder's role is availability,
//! OBSERVABILITY, and ABUSE-CONTROL: it meters/logs DNS and rate-limits per guest so a tenant can't
//! weaponise it into a DoS/amplifier against the host resolver. Real containment (default-deny
//! egress + a forced resolver) is a separate, larger arc; [`DnsPolicy`] is the seam it would attach
//! to without reshaping the data path.
//!
//! ## Hardening (all-tenants-untrusted)
//! * Bind `172.16.0.1` specifically, never `0.0.0.0` — off the public interface. `JKRUNFW` opens
//!   only `${GW}:53` from the bridge, and setup-bridge.sh adds a weak-host `! -i jkbr0 -d ${GW}:53
//!   DROP` (a bridge IP is not loopback-shielded on a multi-homed host — mirrors the DB gateway).
//! * Source-IP fence: serve ONLY the bridge `/24` (`172.16.0.0/24`, IPv4); silently drop the rest.
//! * Relay-only to a FIXED host upstream — never a recursive/open resolver, so no internet source
//!   can elicit a reply (anti open-resolver / anti amplification). Drop responses (QR=1) that
//!   arrive at the listener (anti reflection).
//! * Bounded everywhere: 4096 B UDP ceiling; length-prefixed TCP with a cap + idle deadline;
//!   question parse capped (255 B name / 63 B label / no compression in the question); in-flight
//!   upstream queries + TCP conns semaphore-bounded; a per-query upstream timeout.
//! * Per-source-IP token bucket ([`IpRateLimiter`], reused from the DB gateway).

use crate::Store;
use crate::db_gateway::{IpRateLimiter, project_for_ip_in};
use jkbase_common::config::DB_GATEWAY_IP;
use jkbase_control::store::VmAllocation;
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::Semaphore;
use tracing::{debug, error, info, warn};

/// Standard DNS port. Matches the guest side (`RUNTIME_RESOLV_CONF`, `function_egress::RESOLVER_PORT`).
const DNS_PORT: u16 = 53;
/// The bridge subnet guests live on (`jkbr0` = `172.16.0.1/24`, `setup-bridge.sh`). Only IPv4
/// sources whose first three octets match are served; everything else is dropped.
const BRIDGE_NET: (u8, u8, u8) = (172, 16, 0);
/// Max UDP datagram accepted/emitted — the EDNS0 ceiling. Larger ⇒ dropped (the guest retries TCP).
const MAX_UDP: usize = 4096;
/// A DNS message header is 12 bytes; shorter ⇒ malformed.
const DNS_HDR_LEN: usize = 12;
/// Per-source-IP query rate (token bucket). A legit app does a handful of lookups at startup plus
/// the occasional runtime resolve; this is generous headroom that throttles a flood / tunnel /
/// amplification attempt to a crawl. The bucket map is bounded by the `/24` (≤253 IPs), no pruning.
const PER_IP_RATE_PER_SEC: f64 = 50.0;
const PER_IP_BURST: f64 = 200.0;
/// Global ceiling on concurrent in-flight UPSTREAM queries (each holds a task + ephemeral socket).
const MAX_INFLIGHT: usize = 1024;
/// Global ceiling on concurrent guest TCP/53 connections.
const MAX_TCP_CONNS: usize = 256;
/// Per-query upstream deadline — a slow/dead upstream can't pin a task or the guest.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP idle/read deadline (guest opens a conn but a full length-prefixed message never arrives).
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Refresh cadence for the source-IP→project snapshot (attribution/logging only; matches l4).
const ALLOC_REFRESH: Duration = Duration::from_secs(5);
/// Keep retrying the `:53` bind while systemd-resolved releases the port at startup (setup-bridge.sh
/// restarts resolved without the extra listener in the server's ExecStartPre; this covers any
/// residual race). Best-effort — give up (logged) after the budget, like the DB gateway.
const BIND_RETRY_BUDGET: Duration = Duration::from_secs(15);
const BIND_RETRY_INTERVAL: Duration = Duration::from_millis(500);
/// Fallback upstream when `/etc/resolv.conf` yields no usable nameserver — systemd-resolved's stub.
const FALLBACK_UPSTREAM: &str = "127.0.0.53:53";
/// Response-cache bounds. The upstream (`127.0.0.53`) is itself a caching resolver over loopback, so
/// this is a marginal latency win; kept small + conservative.
const CACHE_MAX_ENTRIES: usize = 4096;
const CACHE_MIN_TTL: Duration = Duration::from_secs(1);
const CACHE_MAX_TTL: Duration = Duration::from_secs(3600);
/// Aggregate-stats log cadence.
const STATS_INTERVAL: Duration = Duration::from_secs(60);

/// Per-project DNS policy seam. v1 is always [`DnsPolicy::Allow`] (resolve-all): a DNS allowlist
/// would be theatre while server-app egress is open NAT (see the module doc). Kept as an explicit
/// type so a future default-deny-egress arc can attach a per-project policy (control-store-backed,
/// keyed by the same unforgeable source-IP attribution) without reshaping the data path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DnsPolicy {
    Allow,
}

impl DnsPolicy {
    fn for_project(_project: Option<&str>) -> Self {
        DnsPolicy::Allow
    }
}

/// Entry point: bind `172.16.0.1:53` (UDP + TCP) and serve forever, forwarding to the host resolver
/// discovered from `/etc/resolv.conf`. Best-effort — a bind failure disables guest DNS and is
/// logged, never fatal (mirrors `db_gateway::serve`).
pub async fn serve(store: Store, host_id: String) {
    let upstream = discover_upstream();
    info!(upstream = %upstream, "dns forwarder: upstream resolver");
    serve_on(store, host_id, DB_GATEWAY_IP, DNS_PORT, upstream).await;
}

/// [`serve`] with the bind IP + port + upstream injected — production pins `172.16.0.1:53`; tests
/// bind `127.0.0.1` on an ephemeral port against a mock upstream.
pub(crate) async fn serve_on(
    store: Store,
    host_id: String,
    ip: &str,
    port: u16,
    upstream: SocketAddr,
) {
    let fw = Arc::new(Forwarder::new(store, host_id, upstream));
    {
        let fw = fw.clone();
        tokio::spawn(async move { fw.refresh_loop().await });
    }
    {
        let fw = fw.clone();
        tokio::spawn(async move { fw.stats_loop().await });
    }
    let ip = ip.to_string();
    let udp = serve_udp(fw.clone(), ip.clone(), port);
    let tcp = serve_tcp(fw.clone(), ip, port);
    tokio::join!(udp, tcp);
}

/// Everything a served query needs, built once and shared (`Arc`) across both listeners.
struct Forwarder {
    store: Store,
    /// This host's id — attribution resolves `src_ip → project` only among THIS host's allocations
    /// ([R3], as in the DB gateway: per-host-island IPs can collide under HA). Empty ⇒ single-node.
    host_id: String,
    upstream: SocketAddr,
    rate: IpRateLimiter,
    /// Bounds concurrent in-flight upstream queries (UDP + TCP legs share the budget).
    inflight: Arc<Semaphore>,
    /// Bounds concurrent guest TCP/53 connections.
    tcp_conns: Arc<Semaphore>,
    /// Source-IP→project snapshot, refreshed on a tick to avoid a control-store read per datagram.
    allocs: RwLock<Arc<Vec<VmAllocation>>>,
    cache: DnsCache,
    q_total: AtomicU64,
    q_dropped: AtomicU64,
    q_cache_hit: AtomicU64,
    q_upstream_err: AtomicU64,
}

impl Forwarder {
    fn new(store: Store, host_id: String, upstream: SocketAddr) -> Self {
        // Prime the attribution snapshot so queries in the first refresh window still map to a
        // project; the refresh loop keeps it current thereafter.
        let allocs = store.list_vm_allocations().unwrap_or_default();
        Self {
            store,
            host_id,
            upstream,
            rate: IpRateLimiter::new(PER_IP_RATE_PER_SEC, PER_IP_BURST),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            tcp_conns: Arc::new(Semaphore::new(MAX_TCP_CONNS)),
            allocs: RwLock::new(Arc::new(allocs)),
            cache: DnsCache::new(),
            q_total: AtomicU64::new(0),
            q_dropped: AtomicU64::new(0),
            q_cache_hit: AtomicU64::new(0),
            q_upstream_err: AtomicU64::new(0),
        }
    }

    /// Only serve IPv4 sources on the runtime bridge `/24`. Belt-and-braces with `JKRUNFW`'s
    /// `-i jkbr0` scope and setup-bridge.sh's weak-host DROP — an off-bridge / spoofed source must
    /// never be served (and would map to no allocation anyway).
    fn src_allowed(ip: IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                (o[0], o[1], o[2]) == BRIDGE_NET
            }
            IpAddr::V6(_) => false,
        }
    }

    fn project_for(&self, ip: IpAddr) -> Option<String> {
        let snap = self.allocs.read().unwrap().clone();
        project_for_ip_in(&snap, ip, &self.host_id)
    }

    async fn refresh_loop(&self) {
        loop {
            tokio::time::sleep(ALLOC_REFRESH).await;
            if let Ok(a) = self.store.list_vm_allocations() {
                *self.allocs.write().unwrap() = Arc::new(a);
            }
        }
    }

    async fn stats_loop(&self) {
        let mut last = 0u64;
        loop {
            tokio::time::sleep(STATS_INTERVAL).await;
            let total = self.q_total.load(Ordering::Relaxed);
            if total == last {
                continue; // stay quiet when idle
            }
            last = total;
            info!(
                queries = total,
                dropped = self.q_dropped.load(Ordering::Relaxed),
                cache_hits = self.q_cache_hit.load(Ordering::Relaxed),
                upstream_errors = self.q_upstream_err.load(Ordering::Relaxed),
                "dns forwarder stats"
            );
        }
    }

    /// Common front-of-pipeline validation for a raw query (shared by UDP + TCP): reject responses
    /// (anti-reflection) and anything but a single-question query. Returns the parsed question.
    fn accept_query(&self, msg: &[u8]) -> Option<(String, u16, u16)> {
        if msg.len() < DNS_HDR_LEN {
            return None;
        }
        if msg[2] & 0x80 != 0 {
            return None; // QR=1 → a response arriving at our listener; drop (no reflector)
        }
        if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
            return None; // QDCOUNT must be exactly 1
        }
        // A parse failure is non-fatal for forwarding (we relay bytes verbatim) — attribution/cache
        // just lose the qname. Returning None here would drop a valid-but-unparsed query, so callers
        // treat `None` as "forward without a question", not "reject".
        parse_question(msg)
    }
}

// ── UDP ───────────────────────────────────────────────────────────────────────────────────────

async fn serve_udp(fw: Arc<Forwarder>, ip: String, port: u16) {
    let sock = match bind_udp_retry(&ip, port).await {
        Some(s) => Arc::new(s),
        None => return,
    };
    info!(%ip, port, "dns forwarder listening (udp)");
    let mut buf = vec![0u8; MAX_UDP];
    loop {
        let (n, src) = match sock.recv_from(&mut buf).await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "dns forwarder: udp recv error");
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
        };
        let src_ip = src.ip();
        if !Forwarder::src_allowed(src_ip) {
            continue; // off-bridge → silent drop
        }
        if n < DNS_HDR_LEN {
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // Rate-limit BEFORE any per-query work (parse / spawn / upstream) so a flood is cheap to shed.
        if !fw.rate.allow(src_ip, Instant::now()) {
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let query = buf[..n].to_vec();
        let question = fw.accept_query(&query);
        if question.is_none() && query[2] & 0x80 != 0 {
            // A response (QR=1) or non-single-question query slipped `accept_query`; drop it.
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let sock = sock.clone();
        let fw = fw.clone();
        tokio::spawn(async move { fw.handle_udp(sock, query, question, src).await });
    }
}

impl Forwarder {
    async fn handle_udp(
        self: Arc<Self>,
        sock: Arc<UdpSocket>,
        query: Vec<u8>,
        question: Option<(String, u16, u16)>,
        src: SocketAddr,
    ) {
        self.q_total.fetch_add(1, Ordering::Relaxed);
        let project = self.project_for(src.ip());
        // v1 policy is always Allow; the match keeps the seam explicit for a future egress fence.
        match DnsPolicy::for_project(project.as_deref()) {
            DnsPolicy::Allow => {}
        }
        if let Some((name, qtype, qclass)) = &question {
            debug!(src = %src.ip(), project = ?project, %name, qtype, qclass, "dns query (udp)");
            if let Some(mut hit) = self.cache.get(name, *qtype, *qclass) {
                hit[0] = query[0]; // graft the live transaction id onto the cached answer
                hit[1] = query[1];
                self.q_cache_hit.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&hit, src).await;
                return;
            }
        }
        let _permit = match self.inflight.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => {
                self.q_dropped.fetch_add(1, Ordering::Relaxed);
                return;
            }
        };
        match upstream_udp(self.upstream, &query).await {
            Some(resp) => {
                let _ = sock.send_to(&resp, src).await;
                if let Some((name, qtype, qclass)) = &question {
                    self.cache.maybe_insert(name, *qtype, *qclass, &resp);
                }
            }
            None => {
                self.q_upstream_err.fetch_add(1, Ordering::Relaxed);
                // Drop silently — the guest's resolver times out and retries, exactly as if the
                // upstream were briefly unreachable.
            }
        }
    }
}

/// Relay one query to the upstream over UDP via a fresh ephemeral socket (upstream is loopback, so
/// this is cheap and isolates transaction-id demux). Returns the response bytes verbatim.
async fn upstream_udp(upstream: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    // Bind unspecified so the OS picks the right source for either a loopback or a real upstream.
    let up = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await.ok()?;
    up.connect(upstream).await.ok()?; // connected → only replies from `upstream` are received
    up.send(query).await.ok()?;
    let mut rbuf = vec![0u8; MAX_UDP];
    match tokio::time::timeout(UPSTREAM_TIMEOUT, up.recv(&mut rbuf)).await {
        Ok(Ok(m)) if m >= DNS_HDR_LEN => {
            rbuf.truncate(m);
            Some(rbuf)
        }
        _ => None,
    }
}

// ── TCP ───────────────────────────────────────────────────────────────────────────────────────

async fn serve_tcp(fw: Arc<Forwarder>, ip: String, port: u16) {
    let listener = match bind_tcp_retry(&ip, port).await {
        Some(l) => l,
        None => return,
    };
    info!(%ip, port, "dns forwarder listening (tcp)");
    loop {
        let (stream, peer) = match listener.accept().await {
            Ok(x) => x,
            Err(e) => {
                warn!(error = %e, "dns forwarder: tcp accept error");
                tokio::time::sleep(Duration::from_millis(50)).await;
                continue;
            }
        };
        if !Forwarder::src_allowed(peer.ip()) {
            continue;
        }
        if !fw.rate.allow(peer.ip(), Instant::now()) {
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let permit = match fw.tcp_conns.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // at the connection ceiling → drop
        };
        let fw = fw.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ = fw.handle_tcp(stream, peer).await;
        });
    }
}

impl Forwarder {
    async fn handle_tcp(&self, mut guest: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        loop {
            // DNS/TCP framing: a 2-byte big-endian length prefix + that many message bytes.
            let mut lenb = [0u8; 2];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, guest.read_exact(&mut lenb)).await {
                Ok(Ok(_)) => {}
                _ => return Ok(()), // idle timeout or EOF → close
            }
            let mlen = u16::from_be_bytes(lenb) as usize;
            if mlen < DNS_HDR_LEN {
                return Ok(()); // malformed frame
            }
            let mut msg = vec![0u8; mlen];
            match tokio::time::timeout(TCP_IDLE_TIMEOUT, guest.read_exact(&mut msg)).await {
                Ok(Ok(_)) => {}
                _ => return Ok(()),
            }
            let question = self.accept_query(&msg);
            if question.is_none() && (msg[2] & 0x80 != 0 || u16::from_be_bytes([msg[4], msg[5]]) != 1)
            {
                return Ok(()); // response or multi-question over TCP → drop the connection
            }
            self.q_total.fetch_add(1, Ordering::Relaxed);
            if let Some((name, qtype, qclass)) = &question {
                debug!(src = %peer.ip(), %name, qtype, qclass, "dns query (tcp)");
            }
            let permit = match self.inflight.clone().try_acquire_owned() {
                Ok(p) => p,
                Err(_) => {
                    self.q_dropped.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            };
            let relayed = upstream_tcp(self.upstream, &msg).await;
            drop(permit);
            match relayed {
                Some(resp) if resp.len() <= u16::MAX as usize => {
                    let rlen = (resp.len() as u16).to_be_bytes();
                    guest.write_all(&rlen).await?;
                    guest.write_all(&resp).await?;
                }
                _ => {
                    self.q_upstream_err.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }
}

/// Relay one query to the upstream over TCP (used for the guest's TCP fallback on truncation).
async fn upstream_tcp(upstream: SocketAddr, query: &[u8]) -> Option<Vec<u8>> {
    let fut = async {
        let mut up = TcpStream::connect(upstream).await?;
        let lenb = (query.len() as u16).to_be_bytes();
        up.write_all(&lenb).await?;
        up.write_all(query).await?;
        let mut rlen = [0u8; 2];
        up.read_exact(&mut rlen).await?;
        let rl = u16::from_be_bytes(rlen) as usize;
        let mut resp = vec![0u8; rl];
        up.read_exact(&mut resp).await?;
        Ok::<Vec<u8>, std::io::Error>(resp)
    };
    match tokio::time::timeout(UPSTREAM_TIMEOUT, fut).await {
        Ok(Ok(resp)) if resp.len() >= DNS_HDR_LEN => Some(resp),
        _ => None,
    }
}

// ── bind helpers ────────────────────────────────────────────────────────────────────────────────

async fn bind_udp_retry(ip: &str, port: u16) -> Option<UdpSocket> {
    let deadline = Instant::now() + BIND_RETRY_BUDGET;
    loop {
        match UdpSocket::bind((ip, port)).await {
            Ok(s) => return Some(s),
            Err(e) => {
                if Instant::now() >= deadline {
                    error!(error = %e, %ip, port, "dns forwarder: udp bind failed — guest DNS disabled");
                    return None;
                }
                debug!(error = %e, %ip, port, "dns forwarder: udp bind busy, retrying");
                tokio::time::sleep(BIND_RETRY_INTERVAL).await;
            }
        }
    }
}

async fn bind_tcp_retry(ip: &str, port: u16) -> Option<TcpListener> {
    let deadline = Instant::now() + BIND_RETRY_BUDGET;
    loop {
        match TcpListener::bind((ip, port)).await {
            Ok(l) => return Some(l),
            Err(e) => {
                if Instant::now() >= deadline {
                    error!(error = %e, %ip, port, "dns forwarder: tcp bind failed — guest DNS/TCP disabled");
                    return None;
                }
                debug!(error = %e, %ip, port, "dns forwarder: tcp bind busy, retrying");
                tokio::time::sleep(BIND_RETRY_INTERVAL).await;
            }
        }
    }
}

// ── query parsing + upstream discovery ────────────────────────────────────────────────────────

/// Bounds-checked, read-only walk of the single question: returns `(lowercased qname, qtype,
/// qclass)`. Rejects a name > 255 B, any label > 63 B, and a compression pointer in the question
/// (questions must not use compression). Never allocates beyond the name string; never follows a
/// pointer, so it cannot loop.
fn parse_question(msg: &[u8]) -> Option<(String, u16, u16)> {
    if msg.len() < DNS_HDR_LEN {
        return None;
    }
    let mut i = DNS_HDR_LEN;
    let mut name = String::new();
    loop {
        let len = *msg.get(i)? as usize;
        if len == 0 {
            i += 1;
            break;
        }
        if len >= 0xC0 {
            return None; // compression pointer — illegal in a question
        }
        if len > 63 {
            return None; // label too long
        }
        i += 1;
        let end = i.checked_add(len)?;
        if end > msg.len() {
            return None;
        }
        if !name.is_empty() {
            name.push('.');
        }
        for &b in &msg[i..end] {
            name.push((b as char).to_ascii_lowercase());
        }
        i = end;
        if name.len() > 255 {
            return None;
        }
    }
    let qtype = u16::from_be_bytes([*msg.get(i)?, *msg.get(i + 1)?]);
    let qclass = u16::from_be_bytes([*msg.get(i + 2)?, *msg.get(i + 3)?]);
    Some((name, qtype, qclass))
}

/// The upstream resolver: the first usable `nameserver` in `/etc/resolv.conf` that is not our own
/// bind IP (loop guard) and not IPv6 (v4-only posture), else `127.0.0.53:53`.
fn discover_upstream() -> SocketAddr {
    let self_ip: IpAddr = DB_GATEWAY_IP.parse().expect("DB_GATEWAY_IP is a valid IP");
    let content = std::fs::read_to_string("/etc/resolv.conf").unwrap_or_default();
    upstream_from_resolv(&content, self_ip)
        .unwrap_or_else(|| FALLBACK_UPSTREAM.parse().expect("FALLBACK_UPSTREAM is a valid addr"))
}

fn upstream_from_resolv(content: &str, self_ip: IpAddr) -> Option<SocketAddr> {
    for line in content.lines() {
        let line = line.trim();
        let Some(rest) = line.strip_prefix("nameserver") else {
            continue;
        };
        let Ok(ip) = rest.trim().parse::<IpAddr>() else {
            continue;
        };
        if ip == self_ip || ip.is_ipv6() {
            continue;
        }
        return Some(SocketAddr::new(ip, DNS_PORT));
    }
    None
}

// ── response cache ──────────────────────────────────────────────────────────────────────────────

type CacheKey = (String, u16, u16); // (lowercased qname, qtype, qclass)
type CacheVal = (Arc<Vec<u8>>, Instant); // (raw response bytes, expiry)

/// Small bounded response cache. Only successful (NOERROR/NXDOMAIN), non-truncated answers are
/// cached; the TTL is the min RR TTL (clamped). Keying is case-insensitive on the qname (DNS is);
/// the served bytes echo the cached question's case, which every client tolerates.
struct DnsCache {
    map: Mutex<HashMap<CacheKey, CacheVal>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, name: &str, qtype: u16, qclass: u16) -> Option<Vec<u8>> {
        let key = (name.to_string(), qtype, qclass);
        let mut m = self.map.lock().unwrap();
        if let Some((bytes, exp)) = m.get(&key) {
            if Instant::now() < *exp {
                return Some(bytes.as_ref().clone());
            }
            m.remove(&key);
        }
        None
    }

    fn maybe_insert(&self, name: &str, qtype: u16, qclass: u16, resp: &[u8]) {
        if resp.len() < DNS_HDR_LEN {
            return;
        }
        if resp[2] & 0x02 != 0 {
            return; // TC=1 truncated — never cache a partial answer
        }
        let rcode = resp[3] & 0x0f;
        if rcode != 0 && rcode != 3 {
            return; // only NOERROR / NXDOMAIN
        }
        let Some(ttl) = min_ttl(resp) else {
            return; // unparseable → fail open (don't cache)
        };
        let ttl = ttl.clamp(CACHE_MIN_TTL, CACHE_MAX_TTL);
        let mut m = self.map.lock().unwrap();
        if m.len() >= CACHE_MAX_ENTRIES {
            let now = Instant::now();
            m.retain(|_, (_, exp)| *exp > now);
            if m.len() >= CACHE_MAX_ENTRIES {
                return; // still full after sweeping expired → skip (simple, bounded)
            }
        }
        m.insert(
            (name.to_string(), qtype, qclass),
            (Arc::new(resp.to_vec()), Instant::now() + ttl),
        );
    }
}

/// The minimum RR TTL across a response's answer/authority/additional sections (skipping the EDNS
/// OPT pseudo-record, whose "TTL" is flags, not a lifetime). `None` on a parse error (fail open).
/// An answer with no cacheable RRs (e.g. a bare NXDOMAIN without an SOA) floors to `CACHE_MIN_TTL`.
fn min_ttl(resp: &[u8]) -> Option<Duration> {
    use hickory_proto::op::Message;
    use hickory_proto::rr::RecordType;
    let msg = Message::from_vec(resp).ok()?;
    let mut min: Option<u32> = None;
    for r in msg
        .answers()
        .iter()
        .chain(msg.name_servers())
        .chain(msg.additionals())
    {
        if r.record_type() == RecordType::OPT {
            continue;
        }
        let t = r.ttl();
        min = Some(min.map_or(t, |m| m.min(t)));
    }
    Some(min.map_or(CACHE_MIN_TTL, |t| Duration::from_secs(u64::from(t))))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Build a minimal DNS query datagram for `name` (A/IN), id `0xABCD`.
    fn query(name: &str) -> Vec<u8> {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        for label in name.split('.') {
            q.push(label.len() as u8);
            q.extend_from_slice(label.as_bytes());
        }
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]); // QTYPE=A, QCLASS=IN
        q
    }

    /// Build a minimal A response: echo the query's id + question, one A RR with the given ttl.
    fn a_response(q: &[u8], ip: [u8; 4], ttl: u32, rcode: u8, tc: bool) -> Vec<u8> {
        // question end
        let mut i = 12usize;
        while q[i] != 0 {
            i += 1 + q[i] as usize;
        }
        let q_end = i + 1 + 4;
        let mut r = Vec::new();
        r.extend_from_slice(&q[0..2]); // id
        r.push(0x84 | (if tc { 0x02 } else { 0 })); // QR=1, AA=1, TC?
        r.push(rcode);
        r.extend_from_slice(&[0, 1]); // QDCOUNT
        r.extend_from_slice(&[0, 1]); // ANCOUNT
        r.extend_from_slice(&[0, 0, 0, 0]); // NS, AR
        r.extend_from_slice(&q[12..q_end]); // question
        r.extend_from_slice(&[0xc0, 0x0c]); // name ptr
        r.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A CLASS=IN
        r.extend_from_slice(&ttl.to_be_bytes()); // TTL
        r.extend_from_slice(&[0, 4]); // RDLENGTH
        r.extend_from_slice(&ip);
        r
    }

    #[test]
    fn parse_question_basic() {
        let q = query("example.com");
        let (name, qtype, qclass) = parse_question(&q).unwrap();
        assert_eq!(name, "example.com");
        assert_eq!(qtype, 1);
        assert_eq!(qclass, 1);
    }

    #[test]
    fn parse_question_lowercases() {
        let q = query("EXample.COM");
        assert_eq!(parse_question(&q).unwrap().0, "example.com");
    }

    #[test]
    fn parse_question_rejects_truncated() {
        let q = query("example.com");
        assert!(parse_question(&q[..q.len() - 2]).is_none()); // missing part of qtype/qclass
        assert!(parse_question(&q[..15]).is_none()); // mid-label
        assert!(parse_question(&[0u8; 8]).is_none()); // shorter than header
    }

    #[test]
    fn parse_question_rejects_compression_pointer() {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[0xC0, 0x0C]); // pointer where a label length is expected
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_question(&q).is_none());
    }

    #[test]
    fn parse_question_rejects_oversized_label() {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(64); // > 63
        q.extend_from_slice(&[b'a'; 64]);
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_question(&q).is_none());
    }

    #[test]
    fn src_allowed_only_bridge_v4() {
        assert!(Forwarder::src_allowed("172.16.0.2".parse().unwrap()));
        assert!(Forwarder::src_allowed("172.16.0.254".parse().unwrap()));
        assert!(!Forwarder::src_allowed("172.16.1.2".parse().unwrap())); // wrong /24
        assert!(!Forwarder::src_allowed("10.0.0.1".parse().unwrap()));
        assert!(!Forwarder::src_allowed("127.0.0.1".parse().unwrap()));
        assert!(!Forwarder::src_allowed("::1".parse().unwrap())); // no v6
    }

    #[test]
    fn upstream_discovery_skips_self_and_v6_falls_back() {
        let self_ip: IpAddr = "172.16.0.1".parse().unwrap();
        // Picks the first usable v4, skipping self + v6.
        let c = "nameserver 172.16.0.1\nnameserver ::1\nnameserver 127.0.0.53\n";
        assert_eq!(
            upstream_from_resolv(c, self_ip).unwrap(),
            "127.0.0.53:53".parse().unwrap()
        );
        // Real host resolver wins when listed first.
        assert_eq!(
            upstream_from_resolv("nameserver 10.0.0.53\n", self_ip).unwrap(),
            "10.0.0.53:53".parse().unwrap()
        );
        // Nothing usable → None (caller falls back).
        assert!(upstream_from_resolv("# empty\nnameserver 172.16.0.1\n", self_ip).is_none());
    }

    #[test]
    fn cache_roundtrips_a_record_and_grafts_id() {
        let q = query("cache.test");
        let resp = a_response(&q, [93, 184, 216, 34], 30, 0, false);
        let cache = DnsCache::new();
        assert!(cache.get("cache.test", 1, 1).is_none());
        cache.maybe_insert("cache.test", 1, 1, &resp);
        let hit = cache.get("cache.test", 1, 1).expect("cached");
        assert_eq!(&hit[2..], &resp[2..]); // body identical; only the id is grafted by the caller
    }

    #[test]
    fn cache_refuses_truncated_and_servfail() {
        let q = query("bad.test");
        let cache = DnsCache::new();
        cache.maybe_insert("bad.test", 1, 1, &a_response(&q, [1, 2, 3, 4], 30, 0, true)); // TC=1
        assert!(cache.get("bad.test", 1, 1).is_none());
        cache.maybe_insert("bad.test", 1, 1, &a_response(&q, [1, 2, 3, 4], 30, 2, false)); // SERVFAIL
        assert!(cache.get("bad.test", 1, 1).is_none());
    }

    #[tokio::test]
    async fn upstream_udp_relays_verbatim() {
        // A mock upstream that echoes a canned A response for whatever it receives.
        let up = UdpSocket::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
        let up_addr = up.local_addr().unwrap();
        tokio::spawn(async move {
            let mut b = vec![0u8; MAX_UDP];
            let (n, peer) = up.recv_from(&mut b).await.unwrap();
            let resp = a_response(&b[..n], [203, 0, 113, 5], 42, 0, false);
            up.send_to(&resp, peer).await.unwrap();
        });
        let q = query("relay.test");
        let resp = upstream_udp(up_addr, &q).await.expect("relayed");
        assert_eq!(&resp[0..2], &q[0..2]); // id echoed
        assert_eq!(resp[2] & 0x80, 0x80); // QR=1
        assert_eq!(&resp[resp.len() - 4..], &[203, 0, 113, 5]); // the A record
    }

    #[tokio::test]
    async fn upstream_udp_times_out_on_silent_upstream() {
        // A bound-but-silent upstream: no reply ⇒ the per-query timeout returns None. Use a short
        // wait by pointing at a black-hole port on loopback that accepts the datagram but never
        // answers (an unbound ephemeral port ⇒ ICMP unreachable ⇒ recv errors ⇒ None quickly).
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap(); // discard-ish; no responder
        assert!(upstream_udp(dead, &query("timeout.test")).await.is_none());
    }
}
