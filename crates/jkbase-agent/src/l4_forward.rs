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
use std::sync::atomic::{AtomicU64, Ordering};
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

/// Largest sealed frame (transit header + payload) that fits a 1500-MTU host↔guest transit leg (and
/// the ~1500 client path) without IP fragmentation: `1500 − 20 (IP) − 8 (UDP) = 1472`. A frame past
/// this EMSGSIZE-drops on the DF-set transit send; the guest is kept under it by the lowered
/// loopback MTU (`L4_GUEST_LOOPBACK_MTU`, host `main.rs`). Diagnostic threshold only — nothing here
/// enforces it.
const TRANSIT_SAFE_FRAME: usize = 1472;

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
/// deserializes to `0`): assume the host ceiling so the agent never reaps below ANY window the host
/// might hold (fail-safe). Bound directly to the host's clamp ceiling so the two can't drift.
const HOST_IDLE_CEIL_FALLBACK_SECS: u64 = jkbase_common::config::L4PortConfig::IDLE_CEIL;

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
    /// Last-activity clock in EITHER direction — millis since [`LandForward::base`]. Bumped by the
    /// forward leg (`deliver`) AND the reply pump (`ReplyPump::run`), so a server→client-only flow
    /// (client silent, app streaming) is not reaped mid-stream (W0.1 bug a): the host keeps such a
    /// flow live on its egress signal, so the agent must too. `Arc<AtomicU64>` because the reply
    /// pump runs as a separate task with no access to the flow map.
    last_seen: Arc<AtomicU64>,
    /// Fired on eviction/supersession to stop this flow's reply pump (which then drops its socket
    /// handle, closing the loopback socket).
    cancel: Arc<Notify>,
    /// The reply pump task. A supersede AWAITS it after cancelling, so the old and new pumps never
    /// read the same socket concurrently — otherwise a reply could be sealed with the superseded
    /// epoch and dropped host-side as `StaleEpoch`.
    pump: tokio::task::JoinHandle<()>,
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
    /// Monotonic epoch for the per-flow `last_seen` millis clock (shared with the reply pumps).
    base: Instant,
    drops: DropCounters,
}

/// Millis since `base` — the shared monotonic clock stamped into `LoopbackFlow::last_seen` by both
/// legs and read by the sweep.
fn elapsed_ms(base: Instant) -> u64 {
    base.elapsed().as_millis() as u64
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
        base: Instant::now(),
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
                _ = sweep.tick() => self.sweep().await,
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
                let now_ms = elapsed_ms(self.base);
                let sock = {
                    let flow = self.flows.get_mut(&hdr.flow_id).expect("present");
                    flow.in_nonce_hw = hdr.nonce;
                    flow.last_seen.store(now_ms, Ordering::Relaxed);
                    flow.sock.clone()
                };
                if let Err(e) = sock.send(payload).await {
                    debug!(error = %e, port = %self.name, "l4 land-forward: loopback send failed");
                }
            }
            Decision::Supersede => {
                // The host rebound this `flow_id` at a higher epoch — which is what a HOST RESTART
                // looks like from in here, since `epoch_base` is reseeded per process. Keep the
                // loopback socket: it is the tuple the guest app has pinned, and re-opening it
                // would move that tuple at exactly the moment the upgrade was meant to be
                // invisible. Only the epoch and nonce state are superseded.
                let reuse = match self.flows.remove(&hdr.flow_id) {
                    Some(old) => {
                        old.cancel.notify_one();
                        // Wait for it to actually stop before the replacement reads the same
                        // socket, or a reply could be sealed with the superseded epoch.
                        //
                        // BOUNDED, because this runs in the single land-forward loop: an unbounded
                        // join would head-of-line block every other flow on this port. Cancellation
                        // is prompt in the normal case (`notify_one` leaves a permit, so there is
                        // no lost wakeup even if the pump is not yet parked), but the pump can be
                        // sitting in a `send_to` on a transit socket the tenant's own TAP queue has
                        // filled. On timeout we simply DON'T reuse: the old socket is still bound,
                        // so the derived bind fails, we take the ephemeral fallback, and this one
                        // flow's tuple moves. A bounded loss of the feature, not of the port.
                        match tokio::time::timeout(PUMP_JOIN_MAX, old.pump).await {
                            Ok(_) => Some(old.sock),
                            Err(_) => {
                                warn!(
                                    port = %self.name, flow_id = hdr.flow_id,
                                    "l4 land-forward: reply pump did not stop in time; \
                                     re-opening the loopback socket (this flow's tuple moves)"
                                );
                                None
                            }
                        }
                    }
                    None => None,
                };
                self.create_flow_on(hdr, payload, src, reuse).await;
            }
            Decision::New => self.create_flow(hdr, payload, src).await,
        }
    }

    /// Admit a fresh `(flow_id, epoch)`: bound-check, open a connected loopback socket, forward the
    /// first payload, and spawn the reply pump. `in_nonce_hw` starts at the first accepted nonce so
    /// the host may start its counter at 0 or 1; every later datagram must strictly exceed it.
    async fn create_flow(&mut self, hdr: L4TransitHeader, payload: &[u8], src: SocketAddr) {
        self.create_flow_on(hdr, payload, src, None).await
    }

    /// As [`Self::create_flow`], but adopts `reuse` if given rather than opening a new loopback
    /// socket — so a supersede keeps the app-visible tuple.
    async fn create_flow_on(
        &mut self,
        hdr: L4TransitHeader,
        payload: &[u8],
        src: SocketAddr,
        reuse: Option<Arc<UdpSocket>>,
    ) {
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
                .min_by_key(|(_, f)| f.last_seen.load(Ordering::Relaxed))
                .map(|(&id, _)| id)
            {
                Some(victim) => {
                    if let Some(old) = self.flows.remove(&victim) {
                        old.cancel.notify_one();
                        // Join before proceeding: the victim's socket stays bound until its pump
                        // exits, and the flow about to be created may derive that very port —
                        // or the victim itself may return next and want it back.
                        let _ = tokio::time::timeout(PUMP_JOIN_MAX, old.pump).await;
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
        let sock = match reuse {
            Some(s) => s,
            None => match connect_loopback(self.guest_port, hdr.flow_id).await {
                Ok(s) => Arc::new(s),
                Err(e) => {
                    warn!(error = %e, port = %self.name, guest_port = self.guest_port, "l4 land-forward: failed to open loopback socket");
                    self.drops.loopback_bind_fail += 1;
                    return;
                }
            },
        };
        if let Err(e) = sock.send(payload).await {
            debug!(error = %e, port = %self.name, "l4 land-forward: loopback send failed");
        }
        let cancel = Arc::new(Notify::new());
        // Shared either-direction activity clock: the reply pump stamps it on every server→client
        // datagram so a client-silent, app-streaming flow is not idle-reaped (W0.1 bug a).
        let last_seen = Arc::new(AtomicU64::new(elapsed_ms(self.base)));
        let pump = tokio::spawn(
            ReplyPump {
                flow_id: hdr.flow_id,
                epoch: hdr.epoch,
                name: self.name.clone(),
                secret: self.secret.clone(),
                loopback: sock.clone(),
                listener: self.listener.clone(),
                reply_to: src,
                cancel: cancel.clone(),
                last_seen: last_seen.clone(),
                base: self.base,
            }
            .run(),
        );
        self.flows.insert(
            hdr.flow_id,
            LoopbackFlow {
                epoch: hdr.epoch,
                sock,
                in_nonce_hw: hdr.nonce,
                last_seen,
                cancel,
                pump,
            },
        );
    }

    /// Idle-evict abandoned flows (leak backstop) + flush the rate-limited drop summary.
    async fn sweep(&mut self) {
        let now = elapsed_ms(self.base);
        let ttl_ms = self.flow_idle_ttl.as_millis() as u64;
        // `retain` cannot await, so collect the retired pumps and join them after.
        let mut retired = Vec::new();
        let mut keep = HashMap::with_capacity(self.flows.len());
        for (id, f) in self.flows.drain() {
            if now.saturating_sub(f.last_seen.load(Ordering::Relaxed)) > ttl_ms {
                f.cancel.notify_one();
                retired.push(f.pump);
            } else {
                keep.insert(id, f);
            }
        }
        self.flows = keep;
        // ONE bounded wait for the whole batch, not per flow: a reap can retire many at once and
        // this runs in the land-forward loop. Joining frees each flow's derived port while nothing
        // is competing for it, so the port is available again if that client comes back.
        if !retired.is_empty() {
            let _ = tokio::time::timeout(PUMP_JOIN_MAX, async {
                for h in retired {
                    let _ = h.await;
                }
            })
            .await;
        }
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
    /// This flow's shared either-direction activity clock (millis since `base`); stamped on every
    /// reply so the land-forward sweep does not idle-reap a flow that is actively streaming
    /// server→client (W0.1 bug a).
    last_seen: Arc<AtomicU64>,
    base: Instant,
}

impl ReplyPump {
    /// `out_nonce` starts at 1 so the host, whose return-path high-water starts at 0 and admits
    /// strictly-greater, accepts the first reply. Ends when `cancel` fires (flow evicted/superseded)
    /// or the loopback socket errors, at which point its socket handle drops and the socket closes.
    async fn run(self) {
        let mut buf = vec![0u8; UDP_MAX_DATAGRAM];
        let mut sealed: Vec<u8> = Vec::with_capacity(UDP_MAX_DATAGRAM + L4_HEADER_LEN);
        let mut out_nonce: u64 = 1;
        // One-shot diagnostic: the first return datagram whose sealed frame won't fit a 1500-MTU
        // transit/client leg. With the guest loopback MTU lowered (`L4_GUEST_LOOPBACK_MTU`) a
        // well-behaved app never trips this; if it fires, the app is NOT sizing to the loopback MTU
        // and its large replies will EMSGSIZE-drop (large-datagram transit failure).
        let mut warned_oversize = false;
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
                    // Return-leg activity: keep this flow off the idle reaper while the app streams
                    // server→client even if the client is silent (W0.1 bug a).
                    self.last_seen.store(elapsed_ms(self.base), Ordering::Relaxed);
                    if n + L4_HEADER_LEN > TRANSIT_SAFE_FRAME && !warned_oversize {
                        warned_oversize = true;
                        warn!(
                            port = %self.name, payload = n, sealed = n + L4_HEADER_LEN,
                            "l4 reply pump: return datagram exceeds the ~1500 transit/client MTU; \
                             it will drop on the 1500-MTU legs — is the app sizing to the loopback MTU?"
                        );
                    }
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
async fn connect_loopback(guest_port: u16, flow_id: u32) -> std::io::Result<UdpSocket> {
    // Bind a source port DERIVED FROM `flow_id` rather than letting the kernel pick, so the tuple
    // the guest app sees is a pure function of the flow — reproduced identically whenever this
    // socket has to be re-created. That is what carries a pinning app (WebRTC/DTLS, QUIC) through
    // the two cases the host cannot reach from its side: our own LRU eviction at
    // `AGENT_L4_MAX_FLOWS`, and a fresh agent after a crash restart. The host keeps `flow_id`
    // stable across its evictions and across an upgrade; this makes the SOCKET stable across ours.
    //
    // mediasoup is the worked example: once ICE is COMPLETED it stores a tuple arriving without
    // use-candidate but never SELECTS it, while answering STUN on the arrival tuple — so a moved
    // tuple leaves ICE looking healthy while DTLS is posted forever to a socket nobody holds.
    // Try the flow's deterministic probe sequence. A single candidate is not enough: the agent
    // holds up to `AGENT_L4_MAX_FLOWS` flows, so birthday collisions are likely at capacity, and
    // they land in exactly the churn case this exists for — A holds P, A is LRU-evicted, B takes
    // P, A returns and finds P gone. A reproducible SECOND choice means A's tuple survives as long
    // as the occupancy around it is stable, instead of falling off a cliff to a kernel port.
    for attempt in 0..PORT_PROBES {
        let Some(candidate) = derived_source_port(flow_id, guest_port, attempt) else {
            break;
        };
        if let Ok(sock) = UdpSocket::bind(("127.0.0.1", candidate)).await
            && sock.connect(("127.0.0.1", guest_port)).await.is_ok()
        {
            return Ok(sock);
        }
    }
    // Fall back to an ephemeral port: every candidate was taken. Correct but not reproducible —
    // this flow's tuple will move if the socket is ever re-created. No worse than before this.
    let sock = UdpSocket::bind(("127.0.0.1", 0)).await?;
    sock.connect(("127.0.0.1", guest_port)).await?;
    Ok(sock)
}

/// Ceiling on waiting for a cancelled reply pump to stop, on every path that retires a flow.
///
/// Waiting at all is what makes the derived source port actually reproducible. Cancelling a pump
/// does not close its socket — the task holds an `Arc<UdpSocket>` clone until it exits, and
/// dropping its `JoinHandle` DETACHES rather than joins. So a flow retired without a join leaves
/// its own derived port bound; if the host's next datagram for that `flow_id` arrives first, the
/// flow collides with its own dying pump and silently takes an ephemeral port. The probe sequence
/// does not save it: linear probing resolves collisions against OTHER flows, not against yourself,
/// so the tuple merely oscillates between candidates instead of falling to a kernel port.
///
/// The ceiling bounds the cost. Every join runs in the single land-forward loop, so an unbounded
/// one would head-of-line block every other flow on the port — and a pump can sit in a `send_to`
/// on a transit socket whose TAP queue the tenant has filled. On timeout we give up the port
/// (that flow's tuple moves) rather than the loop.
const PUMP_JOIN_MAX: Duration = Duration::from_millis(50);

/// How many deterministic candidates a flow tries before giving up on a stable port.
const PORT_PROBES: u32 = 8;

/// The `attempt`-th stable source-port candidate for `flow_id`, or `None` if no usable band exists.
///
/// Band choice is a TENANT-AVAILABILITY decision, not just a correctness one. Above the ephemeral
/// range (61000-65535 by default) is conventionally unused; BELOW it is the whole registered
/// services range, and squatting there would intermittently break a UDP service the tenant starts
/// later in its own VM — STUN/TURN 3478, SIP 5060, RADIUS, OpenVPN — which are precisely the
/// workloads this plane exists to carry. It would surface as "my TURN server sometimes won't
/// start", with no diagnostic. So prefer above, and only fall back below if the tenant has
/// widened its ephemeral range to swallow the top of the space.
///
/// The ephemeral range itself is always excluded and is read from the guest's own sysctl rather
/// than assumed, since the tenant can change it: colliding with ports the kernel hands to the
/// tenant's outbound sockets would be intermittent, and worse for being intermittent.
fn derived_source_port(flow_id: u32, guest_port: u16, attempt: u32) -> Option<u16> {
    let (eph_lo, eph_hi) = ephemeral_range();
    // Prefer above the ephemeral range; fall back below it.
    let (band_lo, band_hi) = {
        let above = (u32::from(eph_hi).saturating_add(1), 65535u32);
        let below = (1024u32, u32::from(eph_lo).saturating_sub(1));
        if above.0 <= above.1 && above.1 - above.0 >= 255 {
            above
        } else if below.0 <= below.1 && below.1 - below.0 >= 255 {
            below
        } else {
            return None;
        }
    };
    let span = band_hi - band_lo + 1;
    // Mix so adjacent flow_ids do not land on adjacent ports; the host allocates them from a
    // monotonic counter, so an unmixed modulo would pack every live flow into one contiguous run.
    let mut h = u64::from(flow_id).wrapping_mul(0x9E37_79B9_7F4A_7C15);
    h ^= h >> 29;
    h = h.wrapping_mul(0xBF58_476D_1CE4_E5B9);
    h ^= h >> 32;
    // Linear probe from the flow's own anchor: deterministic, so the sequence is identical every
    // time this flow's socket is re-created.
    let idx = (h % u64::from(span)) as u32;
    let mut port = band_lo + (idx + attempt) % span;
    // Never the app's own listening port — that bind could only ever fail. SKIP it (deterministic,
    // so the sequence still reproduces) rather than returning `None`, which the caller reads as
    // "no usable band" and would abandon the remaining probes over one unlucky candidate.
    if u32::from(guest_port) == port {
        port = band_lo + (idx + attempt + 1) % span;
    }
    u16::try_from(port).ok()
}

/// The guest's `ip_local_port_range`, or the kernel default if it cannot be read.
fn ephemeral_range() -> (u16, u16) {
    const DEFAULT: (u16, u16) = (32768, 60999);
    let Ok(s) = std::fs::read_to_string("/proc/sys/net/ipv4/ip_local_port_range") else {
        return DEFAULT;
    };
    let mut it = s.split_whitespace();
    match (
        it.next().and_then(|v| v.parse::<u16>().ok()),
        it.next().and_then(|v| v.parse::<u16>().ok()),
    ) {
        (Some(lo), Some(hi)) if lo < hi => (lo, hi),
        _ => DEFAULT,
    }
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

    /// The property the whole guest-side fix rests on: the same `flow_id` must always derive the
    /// same sequence, because that port IS the tuple a pinning app holds. If it ever became order-
    /// or state-dependent, an LRU eviction or a fresh agent would move the tuple again.
    #[test]
    fn derived_source_port_is_stable_and_outside_the_ephemeral_range() {
        let (eph_lo, eph_hi) = ephemeral_range();
        for flow_id in [0u32, 1, 2, 7, 4242, 1_000_003, u32::MAX] {
            for attempt in 0..PORT_PROBES {
                let a = derived_source_port(flow_id, 9999, attempt);
                assert_eq!(
                    a,
                    derived_source_port(flow_id, 9999, attempt),
                    "must be a pure function of (flow_id, attempt)"
                );
                if let Some(p) = a {
                    assert!(p >= 1024, "never a privileged port: {p}");
                    assert!(
                        p < eph_lo || p > eph_hi,
                        "must avoid the guest's ephemeral range {eph_lo}..={eph_hi}, got {p}"
                    );
                }
            }
        }
    }

    /// The band must sit ABOVE the ephemeral range on a default guest, so we never squat the
    /// registered-services range inside the tenant's own VM — STUN/TURN 3478 and SIP 5060 live
    /// there, and they are exactly the workloads this plane carries.
    #[test]
    fn derived_source_port_avoids_the_registered_services_range() {
        let (_eph_lo, eph_hi) = ephemeral_range();
        for flow_id in 0u32..2000 {
            if let Some(p) = derived_source_port(flow_id, 9999, 0) {
                assert!(
                    p > eph_hi,
                    "port {p} is below the ephemeral range — that is the services range"
                );
            }
        }
    }

    /// A collision must have a reproducible SECOND choice. Without it, birthday collisions at
    /// `AGENT_L4_MAX_FLOWS` drop ~one flow at a time onto a kernel-assigned port with no
    /// stability — and they land in exactly the churn case this exists for.
    #[test]
    fn derived_source_port_probes_a_deterministic_sequence() {
        let seq: Vec<u16> = (0..PORT_PROBES)
            .filter_map(|a| derived_source_port(4242, 9999, a))
            .collect();
        assert_eq!(seq.len() as u32, PORT_PROBES, "every attempt yields a candidate");
        let mut dedup = seq.clone();
        dedup.sort_unstable();
        dedup.dedup();
        assert_eq!(dedup.len(), seq.len(), "the sequence must not repeat a port");
        let again: Vec<u16> = (0..PORT_PROBES)
            .filter_map(|a| derived_source_port(4242, 9999, a))
            .collect();
        assert_eq!(seq, again, "the sequence must reproduce exactly");
    }

    /// The failure the eviction joins exist to prevent, at the level `connect_loopback` sees it:
    /// a flow re-created while its OWN previous socket is still bound cannot get its derived port
    /// back, so the tuple moves. Cancelling a pump does not close its socket — the task holds an
    /// `Arc` until it exits, and dropping a `JoinHandle` detaches rather than joins — which is why
    /// LRU and the idle sweep now join before letting the port go.
    #[tokio::test]
    async fn a_flow_reclaims_its_derived_port_only_once_the_old_socket_closes() {
        // Stand in for the guest app so `connect` succeeds.
        let app = UdpSocket::bind(("127.0.0.1", 0)).await.unwrap();
        let guest_port = app.local_addr().unwrap().port();
        let flow_id = 4242u32;

        let first = connect_loopback(guest_port, flow_id).await.unwrap();
        let p1 = first.local_addr().unwrap().port();

        // Re-create while the old socket is STILL OPEN — the lingering-pump case.
        let second = connect_loopback(guest_port, flow_id).await.unwrap();
        let p2 = second.local_addr().unwrap().port();
        assert_ne!(p2, p1, "the old socket still holds p1, so this must land elsewhere");

        // Once both are closed, the flow reclaims its original port — the property that makes the
        // joins worth doing.
        drop(first);
        drop(second);
        let third = connect_loopback(guest_port, flow_id).await.unwrap();
        assert_eq!(
            third.local_addr().unwrap().port(),
            p1,
            "with its own port free, a flow must derive the SAME tuple again"
        );
    }

    /// The app's own listening port is never derived — that bind could only ever fail.
    #[test]
    fn derived_source_port_never_collides_with_the_apps_own_port() {
        for id in 0u32..5000 {
            for attempt in 0..PORT_PROBES {
                if let Some(p) = derived_source_port(id, 21093, attempt) {
                    assert_ne!(p, 21093);
                }
            }
        }
    }
}
