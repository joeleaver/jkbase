//! In-VM L4 (UDP) **land-forward** — the guest end of the raw-UDP scale-to-zero ingress seam.
//!
//! The host relay dials `vm_ip:agent_udp_port` with per-datagram-authenticated transit frames
//! (`jkbase_common::l4_transit`); this task const-time-verifies + strips the header and forwards
//! the raw payload to `127.0.0.1:guest_port` — the loopback port the tenant's service binds in
//! ITS OWN code. The agent is the **sole in-VM mediator**: the tenant service never binds eth0, so
//! the only path to it is this authenticated + L2-source-guarded transit leg (P0-L4-1). A direct
//! eth0 bind would expose an unauthenticated UDP surface to the hostile L2 segment and bypass the
//! host wake/quota/idle machinery.
//!
//! Threat model on this seam: on a shared L2 bridge a co-tenant can address (or spoof toward) the
//! transit listener, so EVERY host→guest datagram is authenticated and every anomalous AUTH path
//! fails **closed** (P0-L4-9): a missing/forged MAC, a replayed nonce, a stale epoch, or a guest
//! that isn't listening ⇒ DROP — never a silent passthrough into the unauthenticated app. A full
//! flow map is NOT a passthrough: it LRU-recycles the least-recently-active (authenticated) flow
//! so a client-churn flood can't wedge the port, since the deferred host→agent teardown signal
//! (§7) leaves the agent to self-bound the map. Anti-replay is a per-`(flow_id, epoch)` monotonic
//! high-water window the caller owns (`l4_transit` is stateless); we own it here (P0-L4-13). The
//! MAC is direction-bound (`L4Dir`) so a reply frame can't be replayed back into the guest, and
//! vice versa (P0-L4-11).
//!
//! Modelled on the agent's loopback DB reach leg (`db_leg_loopback_proxy`, main.rs): bind-or-disable
//! (a bind failure logs + returns, it never crashes the agent), a bounded map fail-closed on
//! overflow, one self-contained task per port.

use jkbase_common::config::L4PortFact;
use jkbase_common::l4_transit::{self, L4_HEADER_LEN, L4Dir, L4TransitHeader};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::UdpSocket;
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};

/// Max distinct `flow_id`s one port's land-forward will hold (one connected loopback socket +
/// one reply task each). Its OWN explicit bound, sized to the microVM's fd/RAM headroom and
/// `<=` the host per-project flow cap, so a flow flood can't exhaust guest fds (P0-L4-5). Only
/// ever filled by flow_ids the AUTHENTICATED host issues — a co-tenant with no transit secret
/// cannot mint one past `l4_transit::open`. On overflow the map LRU-evicts its least-recently-
/// active entry (`create_flow`) rather than DROPping the new flow: with no host teardown signal
/// (§7), a churn flood of short-lived flows would otherwise fill the map with dead entries the
/// host already evicted and wedge the port. Recycling is replay-safe — a still-live evicted flow
/// is re-created on its next datagram, and epoch-distinctness + the host's monotonic
/// per-`(flow_id,epoch)` nonces keep every window unambiguous.
const AGENT_L4_MAX_FLOWS: usize = 256;

/// recv buffer for one datagram. UDP truncates silently past the buffer, so size it to the max
/// UDP payload; the host frames exactly one record per datagram (no coalescing, P0-L4-7).
const UDP_MAX_DATAGRAM: usize = 65535;

/// How long to wait for the guest to bind `127.0.0.1:guest_port` before giving up on the first
/// datagram of a port. The host cannot prove the guest UDP bind is up; the agent polls
/// `/proc/net/udp` (a fact, not an active probe — there is no reliable UDP liveness probe).
const READINESS_TIMEOUT: Duration = Duration::from_secs(10);

/// After a readiness timeout, negative-cache the port "not ready" for this long so a crashed or
/// mis-bound app cannot boot-loop (every packet re-waking → wait-forever → hibernate → repeat).
const READINESS_NEG_TTL: Duration = Duration::from_secs(30);

/// How often to re-poll `/proc/net/udp` while probing for the guest bind.
const READINESS_POLL: Duration = Duration::from_millis(100);

/// First-packet replay buffer caps (P0 [R-replay]): the datagram(s) that arrive during cold boot
/// are buffered and replayed once the guest bind shows; overflow ⇒ drop (the client retransmits).
/// Replay only ever forwards INBOUND to the guest, never emits toward a client, so it is not a
/// reflection vector.
const REPLAY_MAX_PKTS: usize = 4;
const REPLAY_MAX_BYTES: usize = 8 * 1024;

/// Headroom added ON TOP of the host's per-port `idle_timeout` to derive the agent's flow-map idle
/// reaper (`flow_idle_ttl`, W0.1). The agent MUST NOT reap a flow the host still considers live: a
/// premature agent eviction re-creates the flow on the client's next datagram with a fresh reply
/// pump whose `out_nonce` restarts at 1 into the host's already-high `in_nonce_hw`, blanking the
/// return leg until the pump climbs back (a ~N-datagram NonceReplay blackout on re-wake). The
/// headroom covers the sweep granularity ([`SWEEP_INTERVAL`]) plus host↔agent clock skew, so the
/// agent's reaper always trails the host's. A superseding epoch still evicts the prior entry
/// immediately (below) and a full map LRU-evicts the least-recently-active (`create_flow`), so this
/// looser TTL cannot wedge the bounded map — it is only the steady-state reaper for abandoned flows.
const FLOW_IDLE_HEADROOM: Duration = Duration::from_secs(60);

/// Fallback host idle window (seconds) when the fact predates `idle_timeout_secs` (old image ⇒
/// deserializes to `0`): assume the host ceiling (`L4PortConfig::IDLE_CEIL`) so the agent never
/// reaps below ANY window the host might hold (fail-safe).
const HOST_IDLE_CEIL_FALLBACK_SECS: u64 = 600;

/// Derive the agent flow reaper from the host's resolved per-port idle window: `host_idle +
/// headroom`, falling back to the host ceiling when the host didn't tell us (old image, `0`).
fn flow_idle_ttl_for(host_idle_secs: u64) -> Duration {
    let host = if host_idle_secs == 0 {
        HOST_IDLE_CEIL_FALLBACK_SECS
    } else {
        host_idle_secs
    };
    Duration::from_secs(host) + FLOW_IDLE_HEADROOM
}

/// Idle-sweep cadence.
const SWEEP_INTERVAL: Duration = Duration::from_secs(30);

/// Per-port readiness state machine. The guest binds its loopback port in its OWN code some time
/// after boot, so we discover — never assume — that it is up.
#[derive(Clone, Copy)]
enum Readiness {
    /// No datagram seen yet for this port.
    Unknown,
    /// Probing `/proc/net/udp` for the guest bind; inbound is buffered until `deadline`.
    Probing { deadline: Instant },
    /// The guest bind was observed — forward freely.
    Ready,
    /// Readiness timed out; drop inbound (do NOT buffer) until `until`, then re-probe.
    NotReady { until: Instant },
}

/// One live flow's guest-side state, keyed by `flow_id`. Scoped to the current `epoch`: a
/// superseding epoch replaces this whole entry (fresh loopback socket, `in_nonce_hw = 0`), which
/// is what prevents a stale-binding datagram from cross-wiring into a reused id (P0-L4-13).
struct LoopbackFlow {
    /// The `(flow_id, epoch)` this entry authenticates for. A datagram with a higher epoch
    /// supersedes; a lower epoch is a stale rebind and is dropped.
    epoch: u32,
    /// Connected `127.0.0.1:<ephemeral> → 127.0.0.1:guest_port`. Reused for the flow's life so the
    /// app sees a stable source port per flow (client→loopback-port continuity, best-effort v1).
    sock: Arc<UdpSocket>,
    /// Anti-replay high-water for the host→agent direction of THIS `(flow_id, epoch)`.
    in_nonce_hw: u64,
    last_seen: Instant,
    /// Fired on eviction/supersession to stop this flow's reply pump (which then drops its socket
    /// handle, closing the loopback socket).
    cancel: Arc<Notify>,
}

/// Per-drop / rare-event counters, flushed as one rate-limited summary each sweep so a spoof or
/// replay flood can't spam the agent console (the host owns the metering-pipeline counters; these
/// are the guest-side operator signal).
#[derive(Default)]
struct DropCounters {
    header_auth_fail: u64,
    nonce_replay: u64,
    stale_epoch: u64,
    agent_map_full: u64,
    replay_buffer_overflow: u64,
    udp_readiness_timeout: u64,
    loopback_bind_fail: u64,
    /// NOT a drop: count of flows LRU-recycled to admit a new one under a full map (churn signal).
    map_full_evicted: u64,
}

impl DropCounters {
    fn total(&self) -> u64 {
        self.header_auth_fail
            + self.nonce_replay
            + self.stale_epoch
            + self.agent_map_full
            + self.replay_buffer_overflow
            + self.udp_readiness_timeout
            + self.loopback_bind_fail
            + self.map_full_evicted
    }

    fn flush(&mut self, name: &str) {
        if self.total() == 0 {
            return;
        }
        warn!(
            port = %name,
            header_auth_fail = self.header_auth_fail,
            nonce_replay = self.nonce_replay,
            stale_epoch = self.stale_epoch,
            agent_map_full = self.agent_map_full,
            replay_buffer_overflow = self.replay_buffer_overflow,
            udp_readiness_timeout = self.udp_readiness_timeout,
            loopback_bind_fail = self.loopback_bind_fail,
            map_full_evicted = self.map_full_evicted,
            "l4 land-forward: dropped/recycled datagrams (auth-fail drops fail-closed; map_full_evicted = churn LRU recycle)"
        );
        *self = Self::default();
    }
}

/// One port's land-forward state. Owned entirely by its single task — never a field on
/// `AgentState`, so each port is independent and a fault on one can't wedge another.
struct LandForward {
    name: Arc<str>,
    guest_port: u16,
    secret: Arc<Vec<u8>>,
    listener: Arc<UdpSocket>,
    flows: HashMap<u32, LoopbackFlow>,
    readiness: Readiness,
    /// Bounded first-packet buffer: `(raw frame, host source addr)`.
    pending: Vec<(Vec<u8>, SocketAddr)>,
    pending_bytes: usize,
    /// Idle reaper derived from the host's per-port `idle_timeout` (`flow_idle_ttl_for`, W0.1) so
    /// the agent never evicts a flow the host still holds live.
    flow_idle_ttl: Duration,
    drops: DropCounters,
}

/// Start the land-forward for one host-asserted L4 port. Bind failure ⇒ `error!` + return (never
/// crash the agent); empty transit secret ⇒ start nothing (fail-closed — an empty key would let a
/// co-tenant forge the MAC). One task per port; the caller spawns one of these per `_l4.json`
/// entry. v1 serves UDP only; a non-udp fact is ignored rather than opened as a silent TCP path.
pub async fn run_l4_land_forward(fact: L4PortFact, transit_secret: String) {
    if transit_secret.is_empty() {
        error!(
            name = %fact.name,
            "l4 land-forward: empty transit secret; refusing to start (fail-closed)"
        );
        return;
    }
    if !fact.proto.eq_ignore_ascii_case("udp") {
        warn!(name = %fact.name, proto = %fact.proto, "l4 land-forward: only udp is served in v1; not starting");
        return;
    }
    let listener = match UdpSocket::bind(("0.0.0.0", fact.agent_udp_port)).await {
        Ok(s) => Arc::new(s),
        Err(e) => {
            error!(
                error = %e,
                name = %fact.name,
                agent_udp_port = fact.agent_udp_port,
                "l4 land-forward: failed to bind transit listener; disabling this port"
            );
            return;
        }
    };
    let flow_idle_ttl = flow_idle_ttl_for(fact.idle_timeout_secs);
    info!(
        name = %fact.name,
        agent_udp_port = fact.agent_udp_port,
        guest_port = fact.guest_port,
        host_idle_timeout_secs = fact.idle_timeout_secs,
        flow_idle_ttl_secs = flow_idle_ttl.as_secs(),
        "l4 land-forward listening"
    );
    let lf = LandForward {
        name: Arc::from(fact.name.as_str()),
        guest_port: fact.guest_port,
        secret: Arc::new(transit_secret.into_bytes()),
        listener,
        flows: HashMap::new(),
        readiness: Readiness::Unknown,
        pending: Vec::new(),
        pending_bytes: 0,
        flow_idle_ttl,
        drops: DropCounters::default(),
    };
    lf.run().await;
}

impl LandForward {
    /// The one task loop: `select!` over the transit listener recv, the readiness re-poll tick, and
    /// the idle sweep. Mirrors `db_leg_loopback_proxy`'s never-crash posture — a transient recv
    /// error backs off and continues rather than exiting the loop.
    async fn run(mut self) {
        let listener = self.listener.clone();
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        let mut probe = tokio::time::interval(READINESS_POLL);
        probe.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut sweep = tokio::time::interval(SWEEP_INTERVAL);
        sweep.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {
                r = listener.recv_from(&mut buf) => match r {
                    Ok((n, src)) => self.on_inbound(&buf[..n], src).await,
                    Err(e) => {
                        // Back off briefly so a transient recv errno can't busy-spin the loop.
                        debug!(error = %e, port = %self.name, "l4 land-forward: recv error");
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                },
                _ = probe.tick() => self.poll_readiness().await,
                _ = sweep.tick() => self.sweep(),
            }
        }
    }

    /// Route one inbound transit datagram through the readiness gate. On the FIRST datagram we poll
    /// `/proc/net/udp` immediately (a warm VM's app is already bound → zero-delay deliver); if it
    /// isn't up yet we buffer and let the re-poll tick resolve it.
    async fn on_inbound(&mut self, frame: &[u8], src: SocketAddr) {
        match self.readiness {
            Readiness::Ready => self.deliver(frame, src).await,
            Readiness::Unknown => {
                if guest_udp_port_bound(self.guest_port) {
                    self.readiness = Readiness::Ready;
                    self.deliver(frame, src).await;
                } else {
                    self.readiness = Readiness::Probing {
                        deadline: Instant::now() + READINESS_TIMEOUT,
                    };
                    self.buffer(frame, src);
                }
            }
            Readiness::Probing { .. } => self.buffer(frame, src),
            Readiness::NotReady { until } => {
                if Instant::now() >= until {
                    self.readiness = Readiness::Probing {
                        deadline: Instant::now() + READINESS_TIMEOUT,
                    };
                    self.buffer(frame, src);
                } else {
                    // Negative-cached: drop without buffering so a never-binding app can't
                    // boot-loop the wake tax.
                    self.drops.udp_readiness_timeout += 1;
                }
            }
        }
    }

    /// Re-poll `/proc/net/udp` while probing. On the guest bind: go Ready + replay the buffer. On
    /// deadline: drop the buffer + negative-cache (no boot loop).
    async fn poll_readiness(&mut self) {
        let Readiness::Probing { deadline } = self.readiness else {
            return;
        };
        if guest_udp_port_bound(self.guest_port) {
            info!(port = %self.name, guest_port = self.guest_port, "l4 land-forward: guest bind observed; ready");
            self.readiness = Readiness::Ready;
            self.drain_pending().await;
        } else if Instant::now() >= deadline {
            warn!(
                port = %self.name,
                guest_port = self.guest_port,
                "l4 land-forward: readiness timed out; negative-caching (guest never bound loopback)"
            );
            self.drops.udp_readiness_timeout += self.pending.len() as u64;
            self.pending.clear();
            self.pending_bytes = 0;
            self.readiness = Readiness::NotReady {
                until: Instant::now() + READINESS_NEG_TTL,
            };
        }
    }

    /// Replay the buffered first datagrams once ready (in arrival order).
    async fn drain_pending(&mut self) {
        let pending = std::mem::take(&mut self.pending);
        self.pending_bytes = 0;
        for (frame, src) in pending {
            self.deliver(&frame, src).await;
        }
    }

    /// Bounded buffer of an inbound frame during boot. Overflow ⇒ drop (client retransmits).
    fn buffer(&mut self, frame: &[u8], src: SocketAddr) {
        if self.pending.len() >= REPLAY_MAX_PKTS
            || self.pending_bytes + frame.len() > REPLAY_MAX_BYTES
        {
            self.drops.replay_buffer_overflow += 1;
            return;
        }
        self.pending_bytes += frame.len();
        self.pending.push((frame.to_vec(), src));
    }

    /// Authenticate one transit frame and forward its payload to the guest loopback port. Every
    /// failure path drops (P0-L4-9): forged MAC, replayed nonce, stale epoch, full map.
    async fn deliver(&mut self, frame: &[u8], src: SocketAddr) {
        // This leg only ever opens the forward direction; binding the MAC to `HostToAgent`
        // domain-separates it from the return leg, so a co-tenant can't replay a captured
        // agent→host reply back into the guest (cross-direction replay, P0-L4-11).
        let Some((hdr, payload)) = l4_transit::open(&self.secret, L4Dir::HostToAgent, frame) else {
            self.drops.header_auth_fail += 1;
            return;
        };
        // Decide against an immutable borrow so the mutating branches don't nest borrows.
        enum Decision {
            Forward,
            Replay,
            Stale,
            Supersede,
            New,
        }
        let decision = match self.flows.get(&hdr.flow_id) {
            Some(f) if f.epoch == hdr.epoch => {
                if hdr.nonce <= f.in_nonce_hw {
                    Decision::Replay
                } else {
                    Decision::Forward
                }
            }
            Some(f) if hdr.epoch < f.epoch => Decision::Stale,
            Some(_) => Decision::Supersede, // hdr.epoch > f.epoch — host rebound this flow_id
            None => Decision::New,
        };
        match decision {
            Decision::Replay => self.drops.nonce_replay += 1,
            Decision::Stale => self.drops.stale_epoch += 1,
            Decision::Forward => {
                let sock = {
                    let flow = self.flows.get_mut(&hdr.flow_id).expect("present");
                    flow.in_nonce_hw = hdr.nonce;
                    flow.last_seen = Instant::now();
                    flow.sock.clone()
                };
                if let Err(e) = sock.send(payload).await {
                    debug!(error = %e, port = %self.name, "l4 land-forward: loopback send failed");
                }
            }
            Decision::Supersede => {
                if let Some(old) = self.flows.remove(&hdr.flow_id) {
                    old.cancel.notify_one();
                }
                self.create_flow(hdr, payload, src).await;
            }
            Decision::New => self.create_flow(hdr, payload, src).await,
        }
    }

    /// Admit a fresh `(flow_id, epoch)`: bound-check, open a connected loopback socket, forward the
    /// first payload, and spawn the reply pump. `in_nonce_hw` starts at the first accepted nonce so
    /// the host may start its counter at 0 or 1; every later datagram must strictly exceed it.
    async fn create_flow(&mut self, hdr: L4TransitHeader, payload: &[u8], src: SocketAddr) {
        // Map full: LRU-evict the least-recently-active entry to make room rather than DROP this
        // (authenticated) new flow. Dropping would let a churn flood of short-lived flows wedge the
        // port once the map fills with dead entries the host already evicted but sent no teardown
        // signal for (§7). The evicted flow, if still live host-side, is re-created on its next
        // datagram (fresh loopback socket); epoch-distinctness + the host's monotonic
        // per-`(flow_id,epoch)` nonces mean this can't be turned into a replay. Genuine AUTH
        // failures still DROP (in `deliver`) — fail-closed is preserved for those.
        if self.flows.len() >= AGENT_L4_MAX_FLOWS {
            match self
                .flows
                .iter()
                .min_by_key(|(_, f)| f.last_seen)
                .map(|(&id, _)| id)
            {
                Some(victim) => {
                    if let Some(old) = self.flows.remove(&victim) {
                        old.cancel.notify_one();
                    }
                    self.drops.map_full_evicted += 1;
                }
                // Unreachable (cap >= 1 ⇒ a full map has a victim), but stay fail-closed if it ever
                // isn't: DROP rather than grow past the bound.
                None => {
                    self.drops.agent_map_full += 1;
                    return;
                }
            }
        }
        let sock = match connect_loopback(self.guest_port).await {
            Ok(s) => Arc::new(s),
            Err(e) => {
                warn!(error = %e, port = %self.name, guest_port = self.guest_port, "l4 land-forward: failed to open loopback socket");
                self.drops.loopback_bind_fail += 1;
                return;
            }
        };
        if let Err(e) = sock.send(payload).await {
            debug!(error = %e, port = %self.name, "l4 land-forward: loopback send failed");
        }
        let cancel = Arc::new(Notify::new());
        tokio::spawn(
            ReplyPump {
                flow_id: hdr.flow_id,
                epoch: hdr.epoch,
                name: self.name.clone(),
                secret: self.secret.clone(),
                loopback: sock.clone(),
                listener: self.listener.clone(),
                reply_to: src,
                cancel: cancel.clone(),
            }
            .run(),
        );
        self.flows.insert(
            hdr.flow_id,
            LoopbackFlow {
                epoch: hdr.epoch,
                sock,
                in_nonce_hw: hdr.nonce,
                last_seen: Instant::now(),
                cancel,
            },
        );
    }

    /// Idle-evict abandoned flows (leak backstop) + flush the rate-limited drop summary.
    fn sweep(&mut self) {
        let now = Instant::now();
        let ttl = self.flow_idle_ttl;
        self.flows.retain(|_, f| {
            if now.duration_since(f.last_seen) > ttl {
                f.cancel.notify_one();
                false
            } else {
                true
            }
        });
        self.drops.flush(&self.name);
    }
}

/// One flow's reply pump: recv the guest app's reply on the connected loopback socket, seal it with
/// this flow's `(flow_id, epoch)` and a monotonic agent→host nonce, and send it back to the host's
/// guest-facing source addr (`reply_to` — whoever the host dialed us from, captured at flow
/// creation; the host uses ONE guest-facing socket per port, P0-L4-5, so that source is stable for
/// the flow's life).
struct ReplyPump {
    flow_id: u32,
    epoch: u32,
    name: Arc<str>,
    secret: Arc<Vec<u8>>,
    loopback: Arc<UdpSocket>,
    listener: Arc<UdpSocket>,
    reply_to: SocketAddr,
    cancel: Arc<Notify>,
}

impl ReplyPump {
    /// `out_nonce` starts at 1 so the host, whose return-path high-water starts at 0 and admits
    /// strictly-greater, accepts the first reply. Ends when `cancel` fires (flow evicted/superseded)
    /// or the loopback socket errors, at which point its socket handle drops and the socket closes.
    async fn run(self) {
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        let mut sealed: Vec<u8> = Vec::with_capacity(UDP_MAX_DATAGRAM + L4_HEADER_LEN);
        let mut out_nonce: u64 = 1;
        loop {
            tokio::select! {
                _ = self.cancel.notified() => break,
                r = self.loopback.recv(&mut buf) => {
                    let n = match r {
                        Ok(n) => n,
                        Err(e) => {
                            debug!(error = %e, port = %self.name, "l4 reply pump: loopback recv error; ending");
                            break;
                        }
                    };
                    // Sealing adds L4_HEADER_LEN; if that would exceed the max UDP datagram, this
                    // single reply can't be framed on the wire — drop it (don't wedge the flow).
                    if n + L4_HEADER_LEN > UDP_MAX_DATAGRAM {
                        debug!(port = %self.name, len = n, "l4 reply pump: reply too large to frame; dropping datagram");
                        continue;
                    }
                    // Seal the reply on the return leg (`AgentToHost`): domain-separated from the
                    // forward leg so this frame can't be replayed back into the guest (P0-L4-11).
                    l4_transit::seal(
                        &self.secret,
                        L4Dir::AgentToHost,
                        L4TransitHeader { flow_id: self.flow_id, epoch: self.epoch, nonce: out_nonce },
                        &buf[..n],
                        &mut sealed,
                    );
                    out_nonce = out_nonce.wrapping_add(1);
                    if let Err(e) = self.listener.send_to(&sealed, self.reply_to).await {
                        debug!(error = %e, port = %self.name, "l4 reply pump: send to host failed");
                    }
                }
            }
        }
    }
}

/// Open a loopback UDP socket bound to an ephemeral `127.0.0.1` source and connected to
/// `127.0.0.1:guest_port`, so `send`/`recv` reach the guest app and receive its replies. Connecting
/// pins the peer, so a reply from any other source is ignored by the kernel.
async fn connect_loopback(guest_port: u16) -> std::io::Result<UdpSocket> {
    let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
    sock.connect(("127.0.0.1", guest_port)).await?;
    Ok(sock)
}

/// True if the guest has a UDP socket bound on `guest_port` at `127.0.0.1` or `0.0.0.0`. Reads
/// `/proc/net/udp` (v4) then `/proc/net/udp6`; a read failure is treated as "not bound" (the caller
/// keeps probing until its bounded timeout, then negative-caches — fail-closed, never a false
/// ready).
fn guest_udp_port_bound(port: u16) -> bool {
    let read = |p: &str| std::fs::read_to_string(Path::new(p)).unwrap_or_default();
    guest_udp_port_bound_in(&read("/proc/net/udp"), port)
        || guest_udp_port_bound_in(&read("/proc/net/udp6"), port)
}

/// Pure `/proc/net/udp{,6}` parser: true if any line binds `local_address` port `== port` to a
/// loopback or wildcard address. Split out as a pure fn so it is exhaustively unit-testable against
/// captured `/proc` text — the readiness gate's correctness is load-bearing (a false ready forwards
/// into a not-listening app; a false not-ready boot-loops).
///
/// `/proc/net/udp` `local_address` is `HEXADDR:HEXPORT`, little-endian host byte order:
/// `127.0.0.1` → `0100007F`, `0.0.0.0` → `00000000` (v4, 8 hex chars); `::1` →
/// `…01000000`, `::` → all-zero (v6, 32 hex chars). We MUST accept the wildcard `0.0.0.0`/`::`
/// bind (the common default) as well as an explicit loopback bind — matching only loopback would
/// leave a `0.0.0.0`-binding app permanently unreachable (mechanics M2). A bind on a non-loopback,
/// non-wildcard address (e.g. eth0) is NOT ready: the agent forwards to `127.0.0.1:guest_port`, so
/// an eth0-only bind would never receive it (and P0-L4-1 requires loopback-only anyway).
fn guest_udp_port_bound_in(contents: &str, port: u16) -> bool {
    // Skip the header row.
    for line in contents.lines().skip(1) {
        let mut cols = line.split_whitespace();
        let _sl = cols.next(); // "N:" slot index
        let Some(local) = cols.next() else { continue };
        let Some((addr_hex, port_hex)) = local.split_once(':') else {
            continue;
        };
        let Ok(p) = u16::from_str_radix(port_hex, 16) else {
            continue;
        };
        if p == port && addr_is_loopback_or_wildcard(addr_hex) {
            return true;
        }
    }
    false
}

/// True for the little-endian hex `local_address` of a loopback (`127.0.0.1` / `::1`) or wildcard
/// (`0.0.0.0` / `::`) bind, in either the v4 (8-char) or v6 (32-char) `/proc` form.
fn addr_is_loopback_or_wildcard(addr_hex: &str) -> bool {
    match addr_hex.len() {
        8 => {
            let a = addr_hex.to_ascii_uppercase();
            a == "00000000" || a == "0100007F"
        }
        32 => {
            let a = addr_hex.to_ascii_uppercase();
            // `::` (all zero) or `::1` (final 32-bit word = 01000000, host byte order).
            a == "0".repeat(32) || a == "00000000000000000000000001000000"
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn flow_idle_ttl_always_trails_the_host_window() {
        // A known host window → host + headroom, so the agent reaper fires strictly after the host
        // still-live window (no premature eviction → no return-leg nonce blank on re-wake, W0.1).
        assert_eq!(flow_idle_ttl_for(60), Duration::from_secs(120));
        assert_eq!(flow_idle_ttl_for(600), Duration::from_secs(660));
        // Old image (0 ⇒ field absent) falls back to the host ceiling, never below any live window.
        assert_eq!(flow_idle_ttl_for(0), Duration::from_secs(660));
        // Holds across every legal idle_timeout in [15, 600].
        for host in [15u64, 60, 120, 300, 600] {
            assert!(
                flow_idle_ttl_for(host) > Duration::from_secs(host),
                "ttl for host={host} must exceed the host window"
            );
        }
    }

    // A representative /proc/net/udp header (columns beyond local_address are ignored).
    const HEADER: &str = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode ref pointer drops";

    fn udp_line(local_addr_hex: &str, port: u16) -> String {
        format!(
            "   0: {local_addr_hex}:{port:04X} 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 12345 2 0000000000000000 0"
        )
    }

    #[test]
    fn detects_loopback_bind() {
        let contents = format!("{HEADER}\n{}", udp_line("0100007F", 9987));
        assert!(guest_udp_port_bound_in(&contents, 9987));
        // Wrong port → not ready.
        assert!(!guest_udp_port_bound_in(&contents, 9988));
    }

    #[test]
    fn detects_wildcard_bind() {
        // A 0.0.0.0 bind (the common default) MUST count as ready (mechanics M2).
        let contents = format!("{HEADER}\n{}", udp_line("00000000", 53));
        assert!(guest_udp_port_bound_in(&contents, 53));
    }

    #[test]
    fn rejects_non_loopback_non_wildcard_bind() {
        // A bind on an eth0 address (e.g. 10.0.0.2 → 0200000A) is NOT ready: the agent forwards to
        // 127.0.0.1:guest_port, which such a socket never receives (and P0-L4-1 requires loopback).
        let contents = format!("{HEADER}\n{}", udp_line("0200000A", 9987));
        assert!(!guest_udp_port_bound_in(&contents, 9987));
    }

    #[test]
    fn ignores_other_ports_finds_target_among_many() {
        let contents = format!(
            "{HEADER}\n{}\n{}\n{}",
            udp_line("00000000", 68),   // dhcp client, wildcard, wrong port
            udp_line("0100007F", 323),  // chrony, loopback, wrong port
            udp_line("0100007F", 9987), // our target
        );
        assert!(guest_udp_port_bound_in(&contents, 9987));
        assert!(guest_udp_port_bound_in(&contents, 323));
        assert!(!guest_udp_port_bound_in(&contents, 9999));
    }

    #[test]
    fn empty_and_header_only_are_not_ready() {
        assert!(!guest_udp_port_bound_in("", 9987));
        assert!(!guest_udp_port_bound_in(HEADER, 9987));
    }

    #[test]
    fn malformed_lines_do_not_panic_and_are_not_ready() {
        let contents = format!(
            "{HEADER}\n{}\n{}\n{}\n{}",
            "garbage with no colon",
            "   1: nothex:zzzz junk",
            "   2:", // truncated
            ":::::",
        );
        assert!(!guest_udp_port_bound_in(&contents, 9987));
    }

    #[test]
    fn detects_v6_loopback_and_wildcard() {
        // ::1 loopback bind.
        let v6_loopback = "00000000000000000000000001000000";
        let contents = format!("{HEADER}\n{}", udp_line(v6_loopback, 9987));
        assert!(guest_udp_port_bound_in(&contents, 9987));
        // :: wildcard bind.
        let v6_any = "00000000000000000000000000000000";
        let contents = format!("{HEADER}\n{}", udp_line(v6_any, 4711));
        assert!(guest_udp_port_bound_in(&contents, 4711));
        // A v6 GLOBAL address on the right port is NOT ready.
        let v6_global = "0000000000000000FFFF0000010011AC";
        let contents = format!("{HEADER}\n{}", udp_line(v6_global, 9987));
        assert!(!guest_udp_port_bound_in(&contents, 9987));
    }

    #[test]
    fn addr_classifier_matches_only_loopback_and_wildcard() {
        assert!(addr_is_loopback_or_wildcard("00000000"));
        assert!(addr_is_loopback_or_wildcard("0100007F"));
        assert!(addr_is_loopback_or_wildcard("0100007f")); // case-insensitive
        assert!(addr_is_loopback_or_wildcard(&"0".repeat(32)));
        assert!(addr_is_loopback_or_wildcard(
            "00000000000000000000000001000000"
        ));
        assert!(!addr_is_loopback_or_wildcard("0200000A")); // eth0 v4
        assert!(!addr_is_loopback_or_wildcard("")); // empty
        assert!(!addr_is_loopback_or_wildcard("0100007")); // wrong length
    }
}
