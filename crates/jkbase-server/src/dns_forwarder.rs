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
//! ## Availability tradeoff (accepted)
//! Guest DNS is now coupled to this process: while jkbase-server restarts, `172.16.0.1:53` has a
//! brief gap (the old process holds the port until it exits; the new one's [`bind_udp_retry`] wins
//! it back). Unlike the public proxy's :80/:443 (socket-activated for zero-bounce), :53 is NOT
//! socket-activated: DNS is UDP and every client retries, so a sub-second gap on an upgrade is
//! tolerable. Socket-activating :53 is a tracked follow-on, not a v1 requirement.
//!
//! ## Hardening (all-tenants-untrusted)
//! * Bind the bridge gateway IP specifically, never `0.0.0.0` — off the public interface. `JKRUNFW`
//!   opens only `${GW}:53` from the bridge, and setup-bridge.sh adds a weak-host `! -i jkbr0 -d
//!   ${GW}:53 DROP` (a bridge IP is not loopback-shielded on a multi-homed host — mirrors the DB gw).
//! * Source-IP fence: serve ONLY the bridge's own `/24` (derived from the bind IP); drop the rest.
//! * Relay-only to a FIXED host upstream — never a recursive/open resolver, so no internet source
//!   can elicit a reply (anti open-resolver / anti amplification). Drop responses (QR=1) that
//!   arrive at the listener (anti reflection).
//! * Per-source-IP token bucket ([`IpRateLimiter`], reused from the DB gateway) on EVERY query —
//!   per-datagram on UDP, per-message inside the TCP pipeline loop (a TCP connection cannot escape
//!   the budget by pipelining). Per-source-IP concurrent-TCP-connection cap so one guest can't
//!   monopolise the global pool. Bounded parse (255 B name / 63 B label / no compression), bounded
//!   in-flight upstream + TCP conns, per-query upstream timeout, a short first-byte TCP deadline.
//! * Response cache keyed on the RAW wire question bytes (lowercased) — never a lossy dotted string,
//!   so a label containing a dot cannot collide with a multi-label name (anti cross-tenant poison).

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
/// Per-source-IP concurrent guest TCP/53 connections — a fraction of the global ceiling so one
/// guest can't slow-loris the whole pool and starve every other tenant's DNS-over-TCP.
const PER_IP_TCP_MAX: usize = 16;
/// Hard backstop on messages relayed over a single TCP connection (defence-in-depth on top of the
/// per-message rate limit) so a pipelined connection is bounded even if the rate bucket is generous.
const MAX_MSGS_PER_CONN: u32 = 10_000;
/// Per-query upstream deadline — a slow/dead upstream can't pin a task or the guest.
const UPSTREAM_TIMEOUT: Duration = Duration::from_secs(5);
/// TCP idle/read deadline between pipelined messages on an established connection.
const TCP_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
/// Deadline for the FIRST length prefix on a fresh TCP connection — a legit client sends it
/// immediately, so a short deadline sheds slow-loris connections that open and then stall.
const FIRST_BYTE_TIMEOUT: Duration = Duration::from_secs(2);
/// Refresh cadence for the source-IP→project snapshot (attribution/logging only; matches l4).
const ALLOC_REFRESH: Duration = Duration::from_secs(5);
/// Keep retrying the `:53` bind while systemd-resolved releases the port at startup (setup-bridge.sh
/// restarts resolved without the extra listener in the server's ExecStartPre; this covers any
/// residual race, and reclaims the port from a draining old process on an upgrade). Best-effort —
/// give up (logged) after the budget, like the DB gateway.
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

/// A parsed DNS question: the lowercased dotted name (for logging), the type/class, and `end` —
/// the byte offset just past the question (`QNAME`+`QTYPE`+`QCLASS`), used to slice the RAW wire
/// question for the collision-free cache key.
struct Question {
    name: String,
    qtype: u16,
    qclass: u16,
    end: usize,
}

/// Entry point: bind the bridge gateway `172.16.0.1:53` (UDP + TCP) and serve forever, forwarding to
/// the host resolver discovered from `/etc/resolv.conf`. Best-effort — a bind failure disables guest
/// DNS and is logged, never fatal (mirrors `db_gateway::serve`).
pub async fn serve(store: Store, host_id: String) {
    let upstream = discover_upstream();
    info!(upstream = %upstream, "dns forwarder: upstream resolver");
    serve_on(store, host_id, DB_GATEWAY_IP, DNS_PORT, upstream).await;
}

/// [`serve`] with the bind IP + port + upstream injected — production pins `172.16.0.1:53`; tests
/// bind a chosen subnet on an ephemeral port against a mock/real upstream.
pub(crate) async fn serve_on(
    store: Store,
    host_id: String,
    ip: &str,
    port: u16,
    upstream: SocketAddr,
) {
    let fw = Arc::new(Forwarder::new(store, host_id, upstream, ip));
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
    /// The `/24` this forwarder serves, derived from the bind IP (the bridge is always a `/24`). A
    /// source outside it is dropped — the guest's source IP is L2-source-guard-pinned, so this is a
    /// sound, unspoofable fence.
    allowed_prefix: [u8; 3],
    rate: IpRateLimiter,
    /// Bounds concurrent in-flight upstream queries (UDP + TCP legs share the budget).
    inflight: Arc<Semaphore>,
    /// Bounds concurrent guest TCP/53 connections, globally.
    tcp_conns: Arc<Semaphore>,
    /// Per-source-IP concurrent-TCP-connection counts (bounded by the `/24`; entries drop to 0 are
    /// removed) — enforces [`PER_IP_TCP_MAX`] so no single guest monopolises the global pool.
    tcp_per_ip: Mutex<HashMap<IpAddr, usize>>,
    /// Source-IP→project snapshot, refreshed on a tick to avoid a control-store read per datagram.
    allocs: RwLock<Arc<Vec<VmAllocation>>>,
    cache: DnsCache,
    q_total: AtomicU64,
    q_dropped: AtomicU64,
    q_cache_hit: AtomicU64,
    q_upstream_err: AtomicU64,
}

impl Forwarder {
    fn new(store: Store, host_id: String, upstream: SocketAddr, bind_ip: &str) -> Self {
        // The served /24 is the bind IP's network. Production binds 172.16.0.1 ⇒ serve 172.16.0.0/24.
        let allowed_prefix = match bind_ip.parse::<Ipv4Addr>() {
            Ok(v4) => {
                let o = v4.octets();
                [o[0], o[1], o[2]]
            }
            // Non-v4 bind (shouldn't happen in prod) ⇒ the runtime-bridge default.
            Err(_) => [172, 16, 0],
        };
        // Prime the attribution snapshot so queries in the first refresh window still map to a
        // project; the refresh loop keeps it current thereafter.
        let allocs = store.list_vm_allocations().unwrap_or_default();
        Self {
            store,
            host_id,
            upstream,
            allowed_prefix,
            rate: IpRateLimiter::new(PER_IP_RATE_PER_SEC, PER_IP_BURST),
            inflight: Arc::new(Semaphore::new(MAX_INFLIGHT)),
            tcp_conns: Arc::new(Semaphore::new(MAX_TCP_CONNS)),
            tcp_per_ip: Mutex::new(HashMap::new()),
            allocs: RwLock::new(Arc::new(allocs)),
            cache: DnsCache::new(),
            q_total: AtomicU64::new(0),
            q_dropped: AtomicU64::new(0),
            q_cache_hit: AtomicU64::new(0),
            q_upstream_err: AtomicU64::new(0),
        }
    }

    fn src_allowed(&self, ip: IpAddr) -> bool {
        src_in_prefix(ip, self.allowed_prefix)
    }

    fn project_for(&self, ip: IpAddr) -> Option<String> {
        let snap = self.allocs.read().unwrap().clone();
        project_for_ip_in(&snap, ip, &self.host_id)
    }

    /// Acquire a per-source-IP TCP slot, or `None` if the guest is already at [`PER_IP_TCP_MAX`].
    /// The returned guard decrements on drop (and prunes the map entry at zero).
    fn acquire_tcp_ip(self: &Arc<Self>, ip: IpAddr) -> Option<TcpIpGuard> {
        let mut m = self.tcp_per_ip.lock().unwrap();
        let c = m.entry(ip).or_insert(0);
        if *c >= PER_IP_TCP_MAX {
            return None;
        }
        *c += 1;
        Some(TcpIpGuard {
            fw: self.clone(),
            ip,
        })
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

    /// Validate a raw query (shared by UDP + TCP): reject a response (anti-reflection) or anything
    /// but a single-question query, and parse the question. `None` means "not a single-question
    /// query" — callers additionally forward a valid-but-unparsed name verbatim (see the sites).
    fn accept_query(&self, msg: &[u8]) -> Option<Question> {
        if msg.len() < DNS_HDR_LEN {
            return None;
        }
        if msg[2] & 0x80 != 0 {
            return None; // QR=1 → a response arriving at our listener; drop (no reflector)
        }
        if u16::from_be_bytes([msg[4], msg[5]]) != 1 {
            return None; // QDCOUNT must be exactly 1
        }
        parse_question(msg)
    }
}

/// RAII guard for a per-source-IP TCP slot (see [`Forwarder::acquire_tcp_ip`]).
struct TcpIpGuard {
    fw: Arc<Forwarder>,
    ip: IpAddr,
}

impl Drop for TcpIpGuard {
    fn drop(&mut self) {
        let mut m = self.fw.tcp_per_ip.lock().unwrap();
        if let Some(c) = m.get_mut(&self.ip) {
            *c -= 1;
            if *c == 0 {
                m.remove(&self.ip);
            }
        }
    }
}

/// True iff `ip` is an IPv4 address in the served `/24` (`prefix.0/24`). IPv6 is never served.
fn src_in_prefix(ip: IpAddr, prefix: [u8; 3]) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let o = v4.octets();
            [o[0], o[1], o[2]] == prefix
        }
        IpAddr::V6(_) => false,
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
        if !fw.src_allowed(src_ip) {
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
            // A response (QR=1) arriving at the listener; drop it (no reflection).
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
        question: Option<Question>,
        src: SocketAddr,
    ) {
        self.q_total.fetch_add(1, Ordering::Relaxed);
        let project = self.project_for(src.ip());
        // v1 policy is always Allow; the match keeps the seam explicit for a future egress fence.
        match DnsPolicy::for_project(project.as_deref()) {
            DnsPolicy::Allow => {}
        }
        if let Some(q) = &question {
            debug!(src = %src.ip(), project = ?project, name = %q.name, q.qtype, q.qclass, "dns query (udp)");
            let key = qkey(&query, q.end);
            if let Some(cached) = self.cache.get(&key) {
                let out = serve_from_cache(&cached, &query, q.end);
                self.q_cache_hit.fetch_add(1, Ordering::Relaxed);
                let _ = sock.send_to(&out, src).await;
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
                if let Some(q) = &question {
                    self.cache.maybe_insert(qkey(&query, q.end), &resp);
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
        if !fw.src_allowed(peer.ip()) {
            continue;
        }
        // Cheap early shed on the accept itself (per-query rate is enforced inside handle_tcp).
        if !fw.rate.allow(peer.ip(), Instant::now()) {
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        // Per-source-IP slot FIRST (so a flood of accepts from one IP can't drain the global pool),
        // then the global ceiling.
        let Some(ip_guard) = fw.acquire_tcp_ip(peer.ip()) else {
            fw.q_dropped.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        let permit = match fw.tcp_conns.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => continue, // at the global ceiling → drop (ip_guard drops here too)
        };
        let fw = fw.clone();
        tokio::spawn(async move {
            let _permit = permit;
            let _ip_guard = ip_guard;
            let _ = fw.handle_tcp(stream, peer).await;
        });
    }
}

impl Forwarder {
    async fn handle_tcp(&self, mut guest: TcpStream, peer: SocketAddr) -> std::io::Result<()> {
        let mut count: u32 = 0;
        loop {
            // First length prefix has a short deadline (slow-loris); pipelined ones use the idle one.
            let read_deadline = if count == 0 {
                FIRST_BYTE_TIMEOUT
            } else {
                TCP_IDLE_TIMEOUT
            };
            let mut lenb = [0u8; 2];
            match tokio::time::timeout(read_deadline, guest.read_exact(&mut lenb)).await {
                Ok(Ok(_)) => {}
                _ => return Ok(()), // idle/first-byte timeout or EOF → close
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
            count += 1;
            if count > MAX_MSGS_PER_CONN {
                return Ok(()); // hard backstop on a pipelined connection
            }
            // Per-MESSAGE rate limit — a pipelined TCP connection cannot escape the per-IP budget.
            if !self.rate.allow(peer.ip(), Instant::now()) {
                self.q_dropped.fetch_add(1, Ordering::Relaxed);
                return Ok(());
            }
            let question = self.accept_query(&msg);
            if question.is_none() && (msg[2] & 0x80 != 0 || u16::from_be_bytes([msg[4], msg[5]]) != 1)
            {
                return Ok(()); // response or multi-question over TCP → drop the connection
            }
            self.q_total.fetch_add(1, Ordering::Relaxed);
            if let Some(q) = &question {
                debug!(src = %peer.ip(), name = %q.name, q.qtype, q.qclass, "dns query (tcp)");
                let key = qkey(&msg, q.end);
                if let Some(cached) = self.cache.get(&key) {
                    let out = serve_from_cache(&cached, &msg, q.end);
                    self.q_cache_hit.fetch_add(1, Ordering::Relaxed);
                    write_tcp_msg(&mut guest, &out).await?;
                    continue;
                }
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
                    if let Some(q) = &question {
                        self.cache.maybe_insert(qkey(&msg, q.end), &resp);
                    }
                    write_tcp_msg(&mut guest, &resp).await?;
                }
                _ => {
                    self.q_upstream_err.fetch_add(1, Ordering::Relaxed);
                    return Ok(());
                }
            }
        }
    }
}

async fn write_tcp_msg(guest: &mut TcpStream, msg: &[u8]) -> std::io::Result<()> {
    let len = (msg.len() as u16).to_be_bytes();
    guest.write_all(&len).await?;
    guest.write_all(msg).await
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

/// Bounds-checked, read-only walk of the single question. Rejects a name > 255 B, any label > 63 B,
/// and a compression pointer in the question (questions must not use compression). Never follows a
/// pointer, so it cannot loop. `name` is the lowercased dotted form (for logging ONLY — the cache
/// keys on the raw wire bytes via `end`, so a label that itself contains a `.` cannot collide).
fn parse_question(msg: &[u8]) -> Option<Question> {
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
    Some(Question {
        name,
        qtype,
        qclass,
        end: i + 4,
    })
}

/// The collision-free cache key: the RAW wire question bytes (`QNAME`+`QTYPE`+`QCLASS`), ASCII-
/// lowercased for DNS's case-insensitivity. Two distinct wire questions always differ here (a label
/// containing a `.` byte can't collide with a multi-label name — the bug a dotted string would have).
fn qkey(msg: &[u8], q_end: usize) -> Vec<u8> {
    let mut k = msg[DNS_HDR_LEN..q_end.min(msg.len())].to_vec();
    k.make_ascii_lowercase();
    k
}

/// Build the bytes to send for a cache hit: the cached response with (a) the live transaction id
/// grafted in, and (b) the echoed question section rewritten to the REQUESTER's exact question bytes
/// (case fidelity — closes 0x20 case-verification, which a lowercased-key cache would otherwise
/// break). The question lengths match because the cache key matched (same lowercased question bytes).
fn serve_from_cache(cached: &[u8], query: &[u8], q_end: usize) -> Vec<u8> {
    let mut out = cached.to_vec();
    if out.len() >= 2 {
        out[0] = query[0];
        out[1] = query[1];
    }
    if q_end <= query.len() && out.len() >= q_end {
        out[DNS_HDR_LEN..q_end].copy_from_slice(&query[DNS_HDR_LEN..q_end]);
    }
    out
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

type CacheKey = Vec<u8>; // lowercased raw wire question bytes (QNAME+QTYPE+QCLASS)
type CacheVal = (Arc<Vec<u8>>, Instant); // (raw response bytes, expiry)

/// Small bounded response cache. Only successful (NOERROR/NXDOMAIN), non-truncated answers are
/// cached; the TTL is the min RR TTL (clamped). The key is the raw wire question (collision-free);
/// on a full cache the nearest-to-expiry entry is evicted so one tenant can't permanently starve it.
struct DnsCache {
    map: Mutex<HashMap<CacheKey, CacheVal>>,
}

impl DnsCache {
    fn new() -> Self {
        Self {
            map: Mutex::new(HashMap::new()),
        }
    }

    fn get(&self, key: &[u8]) -> Option<Vec<u8>> {
        let mut m = self.map.lock().unwrap();
        if let Some((bytes, exp)) = m.get(key) {
            if Instant::now() < *exp {
                return Some(bytes.as_ref().clone());
            }
            m.remove(key);
        }
        None
    }

    fn maybe_insert(&self, key: CacheKey, resp: &[u8]) {
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
        if m.len() >= CACHE_MAX_ENTRIES && !m.contains_key(&key) {
            let now = Instant::now();
            m.retain(|_, (_, exp)| *exp > now);
            if m.len() >= CACHE_MAX_ENTRIES {
                // Evict the nearest-to-expiry live entry rather than skip, so a tenant filling the
                // cache with long-TTL entries can't permanently deny caching to everyone else.
                if let Some(k) = m
                    .iter()
                    .min_by_key(|(_, (_, exp))| *exp)
                    .map(|(k, _)| k.clone())
                {
                    m.remove(&k);
                } else {
                    return;
                }
            }
        }
        m.insert(key, (Arc::new(resp.to_vec()), Instant::now() + ttl));
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

    /// Build a minimal DNS query datagram for `name` (A/IN), id `0xABCD`. Splits on `.` into labels.
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

    /// Build a query whose QNAME is a SINGLE label with the given raw bytes (which may contain a
    /// `.`), to exercise the cache-key collision case.
    fn query_single_label(label: &[u8]) -> Vec<u8> {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(label.len() as u8);
        q.extend_from_slice(label);
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        q
    }

    /// Build a minimal A response: echo the query's id + question, one A RR with the given ttl.
    fn a_response(q: &[u8], ip: [u8; 4], ttl: u32, rcode: u8, tc: bool) -> Vec<u8> {
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
        r.extend_from_slice(&q[12..q_end]); // question (echoed)
        r.extend_from_slice(&[0xc0, 0x0c]); // name ptr
        r.extend_from_slice(&[0, 1, 0, 1]); // TYPE=A CLASS=IN
        r.extend_from_slice(&ttl.to_be_bytes());
        r.extend_from_slice(&[0, 4]); // RDLENGTH
        r.extend_from_slice(&ip);
        r
    }

    fn parse(q: &[u8]) -> Question {
        parse_question(q).unwrap()
    }

    #[test]
    fn parse_question_basic() {
        let p = parse(&query("example.com"));
        assert_eq!(p.name, "example.com");
        assert_eq!(p.qtype, 1);
        assert_eq!(p.qclass, 1);
        assert_eq!(p.end, query("example.com").len());
    }

    #[test]
    fn parse_question_lowercases() {
        assert_eq!(parse(&query("EXample.COM")).name, "example.com");
    }

    #[test]
    fn parse_question_rejects_truncated() {
        let q = query("example.com");
        assert!(parse_question(&q[..q.len() - 2]).is_none());
        assert!(parse_question(&q[..15]).is_none());
        assert!(parse_question(&[0u8; 8]).is_none());
    }

    #[test]
    fn parse_question_rejects_compression_pointer() {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.extend_from_slice(&[0xC0, 0x0C]);
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_question(&q).is_none());
    }

    #[test]
    fn parse_question_rejects_oversized_label() {
        let mut q = vec![0xAB, 0xCD, 0x01, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0];
        q.push(64);
        q.extend_from_slice(&[b'a'; 64]);
        q.push(0);
        q.extend_from_slice(&[0, 1, 0, 1]);
        assert!(parse_question(&q).is_none());
    }

    #[test]
    fn src_in_prefix_only_bridge_v4() {
        let p = [172, 16, 0];
        assert!(src_in_prefix("172.16.0.2".parse().unwrap(), p));
        assert!(src_in_prefix("172.16.0.254".parse().unwrap(), p));
        assert!(!src_in_prefix("172.16.1.2".parse().unwrap(), p));
        assert!(!src_in_prefix("10.0.0.1".parse().unwrap(), p));
        assert!(!src_in_prefix("127.0.0.1".parse().unwrap(), p));
        assert!(!src_in_prefix("::1".parse().unwrap(), p));
        // A different bind prefix serves a different /24.
        assert!(src_in_prefix("10.77.0.5".parse().unwrap(), [10, 77, 0]));
    }

    #[test]
    fn upstream_discovery_skips_self_and_v6_falls_back() {
        let self_ip: IpAddr = "172.16.0.1".parse().unwrap();
        let c = "nameserver 172.16.0.1\nnameserver ::1\nnameserver 127.0.0.53\n";
        assert_eq!(
            upstream_from_resolv(c, self_ip).unwrap(),
            "127.0.0.53:53".parse().unwrap()
        );
        assert_eq!(
            upstream_from_resolv("nameserver 10.0.0.53\n", self_ip).unwrap(),
            "10.0.0.53:53".parse().unwrap()
        );
        assert!(upstream_from_resolv("# empty\nnameserver 172.16.0.1\n", self_ip).is_none());
    }

    #[test]
    fn cache_key_is_collision_free_across_dot_boundary() {
        // Two DIFFERENT wire questions that a naive dotted-string key would collide: the multi-label
        // name a.b vs a single label whose bytes are "a.b". Their qnames stringify identically...
        let q_multi = query("a.b");
        let q_single = query_single_label(b"a.b");
        assert_eq!(parse(&q_multi).name, parse(&q_single).name); // both "a.b" as a string
        // ...but the raw-wire cache keys MUST differ (else cross-tenant cache poisoning).
        let k_multi = qkey(&q_multi, parse(&q_multi).end);
        let k_single = qkey(&q_single, parse(&q_single).end);
        assert_ne!(k_multi, k_single);
    }

    #[test]
    fn cache_roundtrips_and_serve_rewrites_question_and_id() {
        let q = query("cache.test");
        let resp = a_response(&q, [93, 184, 216, 34], 30, 0, false);
        let cache = DnsCache::new();
        let key = qkey(&q, parse(&q).end);
        assert!(cache.get(&key).is_none());
        cache.maybe_insert(key.clone(), &resp);
        let cached = cache.get(&key).expect("cached");
        // A new query for the same name but different id + case: the served bytes must carry the new
        // id and echo the requester's exact (upper-case) question.
        let q2 = {
            let mut v = query("CACHE.test");
            v[0] = 0x11;
            v[1] = 0x22;
            v
        };
        let out = serve_from_cache(&cached, &q2, parse(&q2).end);
        assert_eq!(&out[0..2], &[0x11, 0x22]); // grafted id
        let q2end = parse(&q2).end;
        assert_eq!(&out[12..q2end], &q2[12..q2end]); // question rewritten to requester's exact bytes
        assert_eq!(&out[out.len() - 4..], &[93, 184, 216, 34]); // answer preserved
    }

    #[test]
    fn cache_refuses_truncated_and_servfail() {
        let q = query("bad.test");
        let cache = DnsCache::new();
        let key = qkey(&q, parse(&q).end);
        cache.maybe_insert(key.clone(), &a_response(&q, [1, 2, 3, 4], 30, 0, true)); // TC=1
        assert!(cache.get(&key).is_none());
        cache.maybe_insert(key.clone(), &a_response(&q, [1, 2, 3, 4], 30, 2, false)); // SERVFAIL
        assert!(cache.get(&key).is_none());
    }

    #[tokio::test]
    async fn upstream_udp_relays_verbatim() {
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
        assert_eq!(&resp[0..2], &q[0..2]);
        assert_eq!(resp[2] & 0x80, 0x80);
        assert_eq!(&resp[resp.len() - 4..], &[203, 0, 113, 5]);
    }

    #[tokio::test]
    async fn upstream_udp_times_out_on_silent_upstream() {
        let dead: SocketAddr = "127.0.0.1:9".parse().unwrap();
        assert!(upstream_udp(dead, &query("timeout.test")).await.is_none());
    }

    /// On-box e2e: the REAL forwarder resolving a REAL guest's query. A veth pair puts a "guest" in
    /// its own netns (10.77.0.2, ingress on a real veth with an in-`/24` source, exactly like a VM on
    /// the bridge); the forwarder binds 10.77.0.1:53 and relays to the host's own resolver. We drive
    /// it two ways: `dig` straight at the forwarder (bind + src-fence + relay), and glibc `getent`
    /// through a netns `resolv.conf` — the EXACT `getaddrinfo` path TeamSpeak stalled on with
    /// EAI_AGAIN. 10.77.0.0/24 (not 172.16.0.0/24) so it never fights the box's systemd-resolved.
    /// Run: `sudo -E env JKB_ONBOX_DNS=1 cargo test -p jkbase-server dns_forwarder_on_box_e2e -- --ignored --nocapture`
    #[tokio::test]
    #[ignore = "on-box dns e2e: needs root + ip/netns/dig/getent + a working host resolver; set JKB_ONBOX_DNS=1"]
    async fn dns_forwarder_on_box_e2e() {
        use tokio::process::Command;
        if std::env::var("JKB_ONBOX_DNS").is_err() {
            eprintln!("skip: set JKB_ONBOX_DNS=1 (needs root; creates a netns + veth)");
            return;
        }
        async fn run(cmd: &str, args: &[&str]) -> (bool, String) {
            match Command::new(cmd).args(args).output().await {
                Ok(o) => (
                    o.status.success(),
                    String::from_utf8_lossy(&o.stdout).into_owned(),
                ),
                Err(e) => (false, e.to_string()),
            }
        }

        let (ns, veth_h, veth_g) = ("jkdnsg", "jkdns-h", "jkdns-g");
        let (host_ip, guest_ip) = ("10.77.0.1", "10.77.0.2");

        // Clean any leftovers, then build the topology.
        let _ = run("ip", &["netns", "del", ns]).await;
        let _ = run("ip", &["link", "del", veth_h]).await;
        run("ip", &["netns", "add", ns]).await;
        run(
            "ip",
            &["link", "add", veth_h, "type", "veth", "peer", "name", veth_g],
        )
        .await;
        run("ip", &["link", "set", veth_g, "netns", ns]).await;
        run("ip", &["addr", "add", &format!("{host_ip}/24"), "dev", veth_h]).await;
        run("ip", &["link", "set", veth_h, "up"]).await;
        run(
            "ip",
            &["-n", ns, "addr", "add", &format!("{guest_ip}/24"), "dev", veth_g],
        )
        .await;
        run("ip", &["-n", ns, "link", "set", veth_g, "up"]).await;
        run("ip", &["-n", ns, "link", "set", "lo", "up"]).await;

        // netns resolv.conf → the forwarder, so glibc getaddrinfo (the TS3 path) uses it.
        let _ = std::fs::create_dir_all(format!("/etc/netns/{ns}"));
        let _ = std::fs::write(
            format!("/etc/netns/{ns}/resolv.conf"),
            format!("nameserver {host_ip}\noptions timeout:2 attempts:2\n"),
        );

        // The real forwarder: bind 10.77.0.1:53, relay to the host's own resolver (127.0.0.53).
        let store =
            crate::Store::open(&std::env::temp_dir().join("jkdns-e2e.redb")).expect("open store");
        let _ = store.save_vm_allocation(&jkbase_control::store::VmAllocation {
            project_id: "dnse2e".into(),
            ip: guest_ip.into(),
            tap_device: veth_g.into(),
            mac: "AA:FC:00:00:77:02".into(),
            host_id: String::new(),
            placement_epoch: 0,
        });
        let upstream = discover_upstream();
        eprintln!("forwarder upstream = {upstream}");
        let fw = tokio::spawn(serve_on(store, String::new(), host_ip, 53, upstream));
        tokio::time::sleep(Duration::from_millis(800)).await; // let both listeners bind

        // (1) dig straight at the forwarder — proves bind + src-fence + relay.
        let (_dig_ok, dig_out) = run(
            "ip",
            &[
                "netns", "exec", ns, "dig", &format!("@{host_ip}"), "example.com", "A", "+short",
                "+time=3", "+tries=2",
            ],
        )
        .await;
        // (2) glibc getaddrinfo via the netns resolv.conf — the exact TS3 EAI_AGAIN path.
        let (ge_ok, ge_out) =
            run("ip", &["netns", "exec", ns, "getent", "hosts", "example.com"]).await;

        // Teardown BEFORE asserting so cleanup always runs.
        fw.abort();
        let _ = std::fs::remove_file(format!("/etc/netns/{ns}/resolv.conf"));
        let _ = std::fs::remove_dir(format!("/etc/netns/{ns}"));
        let _ = run("ip", &["netns", "del", ns]).await;
        let _ = run("ip", &["link", "del", veth_h]).await;

        eprintln!("dig +short:\n{dig_out}\ngetent hosts: ok={ge_ok} {ge_out}");
        let is_ipv4 =
            |l: &str| l.split('.').filter(|o| o.parse::<u8>().is_ok()).count() == 4 && !l.is_empty();
        assert!(
            dig_out.lines().map(str::trim).any(is_ipv4),
            "forwarder did not resolve example.com via dig: {dig_out:?}"
        );
        assert!(
            ge_ok && !ge_out.trim().is_empty(),
            "glibc getaddrinfo failed through the forwarder: ok={ge_ok} out={ge_out:?}"
        );
    }
}
