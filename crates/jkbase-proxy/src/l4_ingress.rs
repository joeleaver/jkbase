//! `L4Ingress` — the per-port UDP **datagram pump** (design §3(a)/§2, P0-L4-1/-5/-7/-11/-13). The
//! UDP analogue of [`crate::db_ingress::DbIngress`], but a *datagram* relay, not a byte-stream
//! splice: `relay_bidirectional` (`wsproxy`) has no datagram boundary and no per-packet reply key,
//! so it cannot be reused (P0-L4-7). One `L4Ingress` owns, per allocated port:
//!
//! - an always-on **edge** `UdpSocket` on `0.0.0.0:external_port` (`SO_REUSEADDR`, **not**
//!   `SO_REUSEPORT` — two sockets load-balancing one port would split a flood and defeat per-port
//!   accounting), client-facing (`recv_from`/`send_to`);
//! - one **guest-facing** `UdpSocket` toward `vm_ip:agent_udp_port` — **one per port, NOT per
//!   flow** (this is what bounds host fd/task cost, P0-L4-5);
//! - a bookkeeping-only **flow table** (`SocketAddr → Flow`, plus a `flow_id → SocketAddr`
//!   reply-demux index). A `Flow` holds NO socket and NO task — just counters, a `RatioCredit`, an
//!   epoch/nonce window, and the RAII plane guards.
//!
//! Two loops + a sweep, ONE task each (never a task-per-flow), and the wake gate **spawns** the
//! boot — it never `.await`s a multi-second cold boot inline in the recv loop (that would
//! head-of-line-block every warm flow on the port, design H1). Lock discipline: everything touches
//! this port's `Mutex<PortState>` FIRST and any [`L4Plane`] mutex second (global order `port →
//! plane`, no cycle); no lock is ever held across an `.await`.

use crate::l4_egress::{BoundedTtlMap, RatioCredit, RatioVerdict, TokenBucket};
use crate::l4_plane::{
    BootAdmit, DropReason, EgressReject, FlowReservation, L4Event, L4FlowGuard, L4Plane,
    L4PortEgressLimits, ReserveReject, WakeInFlight,
};
use jkbase_common::l4_transit::{self, L4Dir, L4TransitHeader};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;
use tracing::warn;

// ---- host constants (design §6; NOT tenant-tunable) -------------------------------------------

/// Provisional-flow idle timeout: a flow that never sustains traffic is evicted this fast, so a
/// spoof flood cannot pin a VM warm past 5s of silence.
const PROVISIONAL_IDLE: Duration = Duration::from_secs(5);
/// Promotion thresholds (established ⇒ pins the VM warm + billing-eligible): cumulative admitted
/// bytes / packets over a minimum age, in EITHER direction (one-way apps supported, §3(d)).
const MIN_ESTABLISH_BYTES: u64 = 1024;
const MIN_ESTABLISH_PKTS: u64 = 3;
const MIN_ESTABLISH_MS: Duration = Duration::from_millis(250);
/// Hard ceiling on a wake; on expiry the boot task force-releases the permit + warm slot.
const BOOT_TIMEOUT: Duration = Duration::from_secs(30);
/// Distinct destination IPs one port tracks an egress bucket for. Bounded + fail-closed on
/// overflow like every other aux map (P0-L4-5/-9): refusing a newcomer's egress is the correct
/// posture, since evicting a live bucket would reset a victim's rate cap.
const PORT_SOURCE_MAP_MAX: usize = 16_384;
/// Idle TTL for a per-port destination bucket. Matches the plane's per-source TTL so a client that
/// pauses and resumes is treated the same by both levels.
const PORT_SOURCE_TTL: Duration = Duration::from_secs(120);
/// How long an evicted flow's identity is remembered so the SAME client 5-tuple gets it BACK on
/// its next datagram instead of a fresh one. The app-visible tuple is derived from `flow_id` (the
/// agent opens one loopback socket per id), so re-minting hands a live app a brand-new remote
/// tuple — and an app that pinned the old one blackholes. mediasoup does exactly this: once ICE is
/// COMPLETED, a binding request from a new tuple WITHOUT use-candidate is stored for receive but
/// never selected (`IceServer::HandleTuple`), while STUN replies still go to the arrival tuple and
/// everything else goes to `GetSelectedTuple()`. So ICE keeps looking healthy while DTLS is posted
/// forever to a socket the host no longer maps (#87).
///
/// MUST stay strictly BELOW the agent's `FLOW_IDLE_HEADROOM` (60s), so a memo hit implies the agent
/// still holds the flow and will take its existing-flow path. If the memo could outlive the agent's
/// entry we would restore an identity the agent has forgotten: it would open a FRESH loopback
/// socket whose pump restarts `out_nonce` at 1 into our restored high-water, and the return leg
/// would blank entirely — strictly worse than the churn this fixes.
const IDENTITY_MEMO_TTL: Duration = Duration::from_secs(45);
/// Cardinality bound on remembered identities. Overflow degrades to today's behaviour (mint a
/// fresh id), never to an unbounded map — same posture as every other aux map (P0-L4-5/-9).
const IDENTITY_MEMO_MAX: usize = 16_384;

/// Idle-sweep tick — well under [`PROVISIONAL_IDLE`] so provisional flows don't overstay (L3).
const SWEEP_TICK: Duration = Duration::from_secs(1);
/// Poll cadence while a coalesced flow waits for a sibling's boot to resolve `vm_ip`.
const WAIT_POLL: Duration = Duration::from_millis(200);
/// Reuse-drain quarantine for an evicted `(flow_id, epoch)` — a late reply for the old owner can't
/// alias a reused id (P0-L4-13; epoch-distinctness already guards this, quarantine is belt-and-braces).
const REUSE_QUARANTINE: Duration = Duration::from_secs(5);
/// Cold-boot first-packet replay buffer, per flow (bounded; overflow ⇒ drop, client retransmits).
const REPLAY_MAX_PKTS: usize = 4;
const REPLAY_MAX_BYTES: usize = 8 * 1024;
/// Per-port one-shot C0-grant rate (the global rate is enforced by [`L4Plane`]).
const C0_PER_PORT_RATE: f64 = 50.0;
const C0_PER_PORT_BURST: f64 = 200.0;
/// recv buffer — the max UDP payload; `recv_from` silently truncates past this (design §5 MTU note:
/// guest TAP MTU ≥ client MTU + transit header).
const BUF_SIZE: usize = 65535;

/// The current backend IP for an (already-woken) project. The server closes over routing/platform;
/// `None` ⇒ not (yet) resolvable. This is exactly the spec §1.3 `resolve_vm_ip` type.
pub type ResolveVmIp =
    Arc<dyn Fn(String) -> Pin<Box<dyn Future<Output = Option<String>> + Send>> + Send + Sync>;

/// Everything the reconcile loop resolves per allocation to materialize one port.
pub struct L4PortSpec {
    /// The deploy-target project (rendered id).
    pub project_id: String,
    /// `vm_identity::base_project_id(project_id)` — the throttle/gauge/warm key.
    pub base_project: String,
    /// Owning tenant (fair-share key; `None` = ownerless).
    pub tenant_id: Option<String>,
    /// The `[l4.*]` stanza name (logs/counters label).
    pub name: String,
    /// Transport wire name (`"udp"` in v1).
    pub proto: String,
    /// Host public edge bind port.
    pub external_port: u16,
    /// The in-VM transit port the host dials (`vm_ip:agent_udp_port`).
    pub agent_udp_port: u16,
    /// The guest loopback port the agent land-forwards to (informational here).
    pub guest_port: u16,
    /// Resolved `L4PortConfig::idle_timeout_secs()` for an ESTABLISHED flow.
    pub idle_timeout: Duration,
    /// Resolved `L4PortConfig::amp_k()` egress:ingress ratio.
    pub amp_k: u8,
    /// Per-VM transit secret (`Store::get_l4_transit_secret`); fail-closed if empty.
    pub transit_secret: String,
    /// Egress limits for this port, resolved at registration from the project's override (or the
    /// platform defaults). Never re-read per datagram.
    pub egress: L4PortEgressLimits,
}

/// A flow's lifecycle state (design §3(c)). Provisional flows do NOT touch `conn_count`; only an
/// established flow pins the VM warm + is billing-eligible.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FlowKind {
    Provisional,
    Established,
}

/// Pure per-flow bookkeeping — NO socket, NO task (P0-L4-5). The guards are declared with
/// `established_guard` BEFORE `reservation` so on eviction the `conn_count` gauge drops before the
/// flow-table slot (`established ≤ total` holds throughout teardown).
/// The part of a flow that must SURVIVE eviction for the app-visible tuple to stay put.
///
/// The two nonce counters are NOT symmetric, which is why only one is here.
///
/// `out_nonce` (host→agent) is safe to resume either way, and is REQUIRED: if the agent still
/// holds the flow, continuing above its high-water is the only thing that forwards at all; if it
/// has forgotten, `create_flow` simply seeds its high-water from whatever we send.
///
/// `in_nonce_hw` (agent→host) is deliberately ABSENT. It would only be safe while the agent still
/// holds the flow, and nothing can establish that: `resolve_vm_ip` reports whether a VM is in the
/// routing table, not whether the agent PROCESS survived, and the agent also drops entries by LRU
/// at `AGENT_L4_MAX_FLOWS` on a perfectly warm VM. Resuming a high high-water into an agent that
/// has moved on hands a fresh pump — which always restarts `out_nonce` at 1 — a wall it must climb
/// datagram by datagram, blanking the return leg for thousands of packets. So a resumed flow's
/// return leg starts at 0, exactly like a fresh one, which is the state the agent's pump is built
/// for.
///
/// The priced cost: a resumed flow's high-water starts at 0, so a captured pre-eviction reply for
/// this `(flow_id, epoch)` would be admitted, and a captured SEQUENCE could then be walked up
/// monotonically until the first genuine reply jumps the bar past it — and on a QUIET flow, which
/// is exactly the shape that idles out and gets resumed, no genuine reply arrives to close it, so
/// the window lasts the life of the resumed incarnation. That is not merely duplicate
/// media — every replayed frame runs the egress chain and is charged to the victim's metered
/// egress and reflection window. It is contained by REACHABILITY, not by the payload being
/// harmless: the frame must clear `l4_transit::open(secret, AgentToHost, …)`, so a forged one dies
/// at `HeaderAuthFail`, and delivering a CAPTURED one to the host's guest-facing socket needs a
/// source address a runtime VM cannot emit — the per-TAP ebtables guard
/// (`-i <tap> -p IPv4 ! --ip-src <ip> -j DROP`) is hooked into INPUT as well as FORWARD, and
/// `JKRUNFW` admits guest→host only for DNS, the public proxy and the DB gateway. So the replay
/// needs host-level access, which is already total compromise. Weighed against the alternative,
/// which blanks the return leg for thousands of datagrams whenever the agent has moved on.
#[derive(Clone, Copy)]
struct FlowIdentity {
    flow_id: u32,
    epoch: u32,
    out_nonce: u64,
}

struct Flow {
    flow_id: u32,
    epoch: u32,
    kind: FlowKind,
    created: Instant,
    /// Un-throttled last-seen clock, stamped on EVERY admitted datagram in either direction (D7).
    last_seen: Instant,
    /// Agent→host anti-replay high-water for `(flow_id, epoch)` (P0-L4-13).
    in_nonce_hw: u64,
    /// Host→agent monotonic nonce counter (first sent nonce is 1, so the agent's `hw=0` accepts it).
    out_nonce: u64,
    bytes_in: u64,
    bytes_out: u64,
    pkts: u64,
    egress: RatioCredit,
    /// Cold-boot first-packet replay buffer (bounded), flushed on readiness.
    buffer: Vec<Vec<u8>>,
    buffer_bytes: usize,
    established_guard: Option<L4FlowGuard>,
    /// Held purely for its RAII `Drop` — releasing the plane flow-table slot + warm-set membership
    /// when the flow is evicted (never read, like `WakeInFlight`'s permit).
    _reservation: FlowReservation,
}

impl Flow {
    fn provisional(flow_id: u32, epoch: u32, reservation: FlowReservation, now: Instant) -> Self {
        Self {
            flow_id,
            epoch,
            kind: FlowKind::Provisional,
            created: now,
            last_seen: now,
            in_nonce_hw: 0,
            out_nonce: 0,
            bytes_in: 0,
            bytes_out: 0,
            pkts: 0,
            egress: RatioCredit::new(),
            buffer: Vec::new(),
            buffer_bytes: 0,
            established_guard: None,
            _reservation: reservation,
        }
    }
}

/// Per-port mutable state, behind one `Mutex`. Written by the reach loop, return loop, sweep, and
/// the boot task's readiness flush — all of which take THIS lock before any plane mutex.
struct PortState {
    flows: HashMap<SocketAddr, Flow>,
    /// Reply-demux index: `flow_id → client SocketAddr` (P0-L4-7).
    by_flow_id: HashMap<u32, SocketAddr>,
    next_flow_id: u32,
    /// Per-process epoch base for FRESH flow_ids (P0-L4-13). Seeded from wall-clock seconds at
    /// bind, so it MONOTONICALLY INCREASES across a host-process restart: a re-adopted VM's agent
    /// still holding pre-restart `(flow_id, epoch)` entries (up to its ~660s idle TTL) sees the new
    /// epoch `>` its stored one and SUPERSEDES, rather than dropping our reset-nonce traffic as
    /// stale/replay until it idle-evicts.
    epoch_base: u32,
    /// `flow_id → current epoch` (bumped on reuse); pruned to active+quarantined in the sweep.
    epoch_for: HashMap<u32, u32>,
    /// `(flow_id, epoch, drain_until)` reuse quarantine.
    quarantine: Vec<(u32, u32, Instant)>,
    /// Recently-evicted clients' [`FlowIdentity`], so a returning 5-tuple resumes rather than
    /// churns. Bounded + TTL'd; see [`IDENTITY_MEMO_TTL`].
    identity: BoundedTtlMap<SocketAddr, FlowIdentity>,
    /// The resolved `vm_ip:agent_udp_port`; `None` until a boot proves readiness.
    vm_dst: Option<SocketAddr>,
    /// A boot task is running for this port (single-flight of the boot/flush per port).
    booting: bool,
    /// Per-port one-shot C0-grant rate limiter.
    c0_rate: TokenBucket,
    /// This port's egress toward each destination IP, at the PROJECT's resolved rate.
    ///
    /// Lives here rather than on the plane because its rate is per-project: a plane-wide map keyed
    /// only by IP would hand whichever project touched an address first the right to fix the rate
    /// for everyone else. A port belongs to exactly one project, so keying by IP alone is correct
    /// here — and costs no per-datagram allocation, which a `(project, IP)` key would.
    ///
    /// Bounding a project's egress toward a THIRD party is not this map's job; the plane's
    /// platform victim backstop does that, after this, and no override can widen it.
    per_source: BoundedTtlMap<IpAddr, TokenBucket>,
    /// This port's egress limits, LIVE.
    ///
    /// Deliberately here rather than frozen into [`L4PortSpec`] at bind. The reconcile loop only
    /// resolves a spec for a port that is not already live, and `allocate_port` is sticky (a
    /// redeploy updates the allocation row in place rather than removing it), so a spec-frozen
    /// limit could never change for the lifetime of a port — an admin LOWERING a limit during an
    /// incident would get 200 OK and no effect on the live socket. Keeping it in `PortState`
    /// costs the datagram path nothing: `return_decide` already holds this lock.
    egress: L4PortEgressLimits,
}

/// The edge half of one L4 port.
pub struct L4Ingress {
    spec: L4PortSpec,
    plane: Arc<L4Plane>,
    edge: Arc<UdpSocket>,
    guest: Arc<UdpSocket>,
    state: Mutex<PortState>,
    resolve_vm_ip: ResolveVmIp,
    cancel: CancellationToken,
}

/// What the reach-loop decision (under the port lock) tells the loop to do afterwards (outside it).
enum ReachOutcome {
    /// A MISS that reserved a flow slot — the loop must resolve liveness (`resolve_vm_ip`, async,
    /// OUTSIDE the port lock) then call [`L4Ingress::reach_admit`]: a warm VM forwards WITHOUT
    /// spending a wake-rate token or booting; a cold VM runs the wake gate. Carries the RAII
    /// reservation across the async gap.
    CheckLiveness {
        project_id: String,
        src: SocketAddr,
        reservation: FlowReservation,
    },
    /// Forward the just-received datagram to the guest with this framed header.
    Forward {
        flow_id: u32,
        epoch: u32,
        nonce: u64,
        dst: SocketAddr,
    },
    /// Admitted a provisional flow; spawn the boot task holding this single-flight guard.
    BootSpawn {
        guard: WakeInFlight,
        project_id: String,
    },
    /// Admitted a provisional flow; a sibling boot is already in flight — poll for `vm_ip`.
    BootWait { project_id: String },
    /// Buffered during boot, or nothing to send.
    Buffered,
    /// Dropped (a counter was already incremented).
    Dropped,
}

impl L4Ingress {
    /// Bind the edge + guest-facing sockets. Fail-closed: an `EADDRINUSE` on the edge bind is a
    /// hard error (surfaced by the reconcile loop as a deploy failure, never silent no-ingress,
    /// P0-L4-9). `SO_REUSEADDR` yes / `SO_REUSEPORT` NO.
    pub async fn bind(
        spec: L4PortSpec,
        plane: Arc<L4Plane>,
        resolve_vm_ip: ResolveVmIp,
        cancel: CancellationToken,
    ) -> io::Result<Arc<Self>> {
        // Fail-closed on an empty transit secret (P0-L4-9/-11): HMAC accepts any key including the
        // empty one, so an empty secret would produce a "valid" tag anyone can forge — never serve
        // a port whose host↔guest leg is unauthenticated. The reconcile loop should also skip these
        // (§4.2), but the seam refuses independently.
        if spec.transit_secret.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "L4 transit secret is empty (fail-closed: won't serve an unauthenticated port)",
            ));
        }
        let edge = match bind_edge_socket(spec.external_port) {
            Ok(s) => s,
            Err(e) => {
                if e.kind() == io::ErrorKind::AddrInUse {
                    plane.count(DropReason::EdgeBindEaddrinuse);
                }
                return Err(e);
            }
        };
        // Guest-facing socket: ephemeral, unconnected; the kernel picks the host bridge source IP
        // by route to `vm_ip`. Used with `send_to(vm_ip:agent_udp_port)` + `recv_from`.
        let guest = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
        let now = Instant::now();
        // Seed the epoch base (monotonic across restart) + a per-process flow_id start; see
        // `process_epoch_seed` / the `epoch_base` field doc (P0-L4-13, agent-interop obligation).
        let (epoch_base, flow_id_seed) = process_epoch_seed();
        let state = PortState {
            flows: HashMap::new(),
            by_flow_id: HashMap::new(),
            next_flow_id: flow_id_seed,
            epoch_base,
            epoch_for: HashMap::new(),
            quarantine: Vec::new(),
            identity: BoundedTtlMap::new(IDENTITY_MEMO_MAX, IDENTITY_MEMO_TTL),
            vm_dst: None,
            booting: false,
            c0_rate: TokenBucket::new(C0_PER_PORT_RATE, C0_PER_PORT_BURST, now),
            per_source: BoundedTtlMap::new(PORT_SOURCE_MAP_MAX, PORT_SOURCE_TTL),
            egress: spec.egress,
        };
        Ok(Arc::new(Self {
            spec,
            plane,
            edge: Arc::new(edge),
            guest: Arc::new(guest),
            state: Mutex::new(state),
            resolve_vm_ip,
            cancel,
        }))
    }

    /// Run the reach + return pump loops and the idle sweep until `cancel`.
    /// Apply new egress limits to this LIVE port. Returns `true` if anything changed.
    ///
    /// Called from the reconcile loop when an admin edits a project's override. Without this the
    /// knob is write-only: the loop resolves a spec only for a port that is not already live, and
    /// `allocate_port` is sticky, so a port's limits would be frozen from first bind until the
    /// allocation is deleted or the host restarts — an operator LOWERING a limit mid-incident
    /// would get 200 OK and no effect.
    ///
    /// Only the configuration changes; the live token buckets keep their current fill. A LOWERED
    /// rate therefore binds from the next refill rather than clawing back already-granted tokens
    /// (bounded by the burst, so at most one burst of over-send survives a tightening).
    pub fn update_egress_limits(&self, new: L4PortEgressLimits) -> bool {
        let mut st = self.state.lock().unwrap();
        if st.egress == new {
            return false;
        }
        st.egress = new;
        true
    }

    pub async fn run(self: Arc<Self>) {
        let s1 = self.clone();
        let s2 = self.clone();
        let s3 = self.clone();
        tokio::select! {
            _ = s1.reach_loop() => {},
            _ = s2.return_loop() => {},
            _ = s3.sweep_loop() => {},
            _ = self.cancel.cancelled() => {},
        }
    }

    // ---- reach loop (edge → guest) ----

    async fn reach_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF_SIZE];
        let mut seal = Vec::with_capacity(BUF_SIZE + l4_transit::L4_HEADER_LEN);
        loop {
            let (n, src) = match self.edge.recv_from(&mut buf).await {
                Ok(v) => v,
                // An unconnected UDP recv rarely errors; a real one shouldn't hot-spin the loop.
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
            let now = Instant::now();
            // On a MISS, resolve backend liveness OUTSIDE the port lock, then admit; a HIT (and the
            // drop paths) return a terminal outcome directly.
            let outcome = match self.reach_decide(src, &buf[..n], now) {
                ReachOutcome::CheckLiveness {
                    project_id,
                    src,
                    reservation,
                } => {
                    let live = (self.resolve_vm_ip)(project_id.clone()).await;
                    let now2 = Instant::now();
                    self.reach_admit(src, &buf[..n], now2, reservation, project_id, live)
                }
                terminal => terminal,
            };
            match outcome {
                ReachOutcome::Forward {
                    flow_id,
                    epoch,
                    nonce,
                    dst,
                } => {
                    l4_transit::seal(
                        self.spec.transit_secret.as_bytes(),
                        L4Dir::HostToAgent,
                        L4TransitHeader {
                            flow_id,
                            epoch,
                            nonce,
                        },
                        &buf[..n],
                        &mut seal,
                    );
                    let _ = self.guest.send_to(&seal, dst).await;
                }
                ReachOutcome::BootSpawn { guard, project_id } => {
                    tokio::spawn(self.clone().boot_task(guard, project_id));
                }
                ReachOutcome::BootWait { project_id } => {
                    tokio::spawn(self.clone().wait_task(project_id));
                }
                // `reach_admit` never returns CheckLiveness; the other arms are terminal.
                ReachOutcome::CheckLiveness { .. }
                | ReachOutcome::Buffered
                | ReachOutcome::Dropped => {}
            }
        }
    }

    /// The synchronous reach-loop decision (holds the port lock; NO `.await`). A HIT is finalized
    /// here (forward to the cached live `vm_dst`, or buffer during boot); a MISS only RESERVES a
    /// flow slot and returns [`ReachOutcome::CheckLiveness`] — the wake-rate token / boot are
    /// deferred to [`Self::reach_admit`] after an async liveness resolve, so a datagram to an
    /// already-WARM VM neither burns a wake-rate token nor forwards to a stale `vm_dst`.
    fn reach_decide(
        self: &Arc<Self>,
        src: SocketAddr,
        payload: &[u8],
        now: Instant,
    ) -> ReachOutcome {
        let n = payload.len();
        let base = &self.spec.base_project;
        let tenant = self.spec.tenant_id.as_deref();
        let amp_k = self.spec.amp_k;

        let mut st = self.state.lock().unwrap();
        let PortState { flows, vm_dst, .. } = &mut *st;

        // ---- HIT: a known flow ----
        if let Some(flow) = flows.get_mut(&src) {
            flow.last_seen = now;
            flow.bytes_in = flow.bytes_in.saturating_add(n as u64);
            flow.pkts = flow.pkts.saturating_add(1);
            flow.egress.on_ingress(n, amp_k);
            self.plane.note_ingress(base, n, amp_k, now);
            return match *vm_dst {
                Some(dst) => {
                    // Forwarding to the live VM — promote only here (not while buffering during boot,
                    // nor against a dead VM). A HIT implies a flow, which kept the VM warm at the
                    // `vm_dst` its creating MISS validated, so `dst` is live.
                    self.maybe_promote(flow, base, tenant, now);
                    flow.out_nonce += 1;
                    ReachOutcome::Forward {
                        flow_id: flow.flow_id,
                        epoch: flow.epoch,
                        nonce: flow.out_nonce,
                        dst,
                    }
                }
                None => {
                    self.buffer_push(flow, payload);
                    ReachOutcome::Buffered
                }
            };
        }

        // ---- MISS: reserve the flow slot (bounds the table), then defer to reach_admit ----
        // No wake-rate here — it is spent only if the async liveness resolve finds the VM cold.
        match self.plane.try_reserve_flow(base, tenant, now) {
            Ok(reservation) => ReachOutcome::CheckLiveness {
                project_id: self.spec.project_id.clone(),
                src,
                reservation,
            },
            Err(ReserveReject::Project) => {
                self.plane.count(DropReason::FlowFullProject);
                ReachOutcome::Dropped
            }
            Err(ReserveReject::Global) => {
                self.plane.count(DropReason::FlowFullGlobal);
                ReachOutcome::Dropped
            }
            Err(ReserveReject::WarmCeiling | ReserveReject::Ram) => {
                self.plane.count(DropReason::WarmFullGlobal);
                ReachOutcome::Dropped
            }
        }
    }

    /// Finalize a reserved MISS after the async liveness resolve (holds the port lock; NO `.await`).
    /// `live` is `resolve_vm_ip(project)`: `Some(ip)` ⇒ the VM is WARM (the server removes a project
    /// from the routing table on hibernate), so forward WITHOUT a wake-rate token or a boot and
    /// refresh the cached `vm_dst`; `None` ⇒ the VM is cold, so run the wake gate (wake-rate +
    /// single-flight + budget). A brand-new flow doesn't promote (age 0). On any drop the local
    /// `flow` unwinds, releasing its reservation.
    fn reach_admit(
        self: &Arc<Self>,
        src: SocketAddr,
        payload: &[u8],
        now: Instant,
        reservation: FlowReservation,
        project_id: String,
        live: Option<String>,
    ) -> ReachOutcome {
        let n = payload.len();
        let base = &self.spec.base_project;
        let tenant = self.spec.tenant_id.as_deref();
        let amp_k = self.spec.amp_k;

        let mut st = self.state.lock().unwrap();
        let PortState {
            flows,
            by_flow_id,
            next_flow_id,
            epoch_base,
            epoch_for,
            vm_dst,
            booting,
            identity,
            ..
        } = &mut *st;

        // DEFENSIVE, and deliberately unreachable today. `reach_loop` is a single sequential task
        // (`recv_from` -> `reach_decide` -> `.await resolve_vm_ip` -> `reach_admit`) and its only
        // caller, so it cannot hold two datagrams inside the decide->admit window however long the
        // resolve takes -- measured at 860ns uncontended, 92us under a routing writer. The `.await`
        // does release the port lock; there is simply no second thread of control to take it.
        // Parallelising this loop is a live temptation (every warm flow is head-of-line blocked
        // behind that inline resolve), and the day someone does, an unconditional mint here
        // corrupts flow identity: the agent opens a loopback socket PER `flow_id`, so one peer
        // acquires two source ports -- two remote tuples -- toward the guest app while `flows[src]`
        // keeps only the last. Both agent reply pumps then seal against the single host
        // `in_nonce_hw`, and a fresh id carries the shared `epoch_base` so the epoch check cannot
        // separate them: the laggard's replies all drop as `NonceReplay`. The overwritten flow's id
        // leaks too -- `sweep` reclaims ids only for flows it evicts from `flows`.
        //
        // NOT the cause of #87, which stays open. That was this change's original claim and it is
        // disproven: the window is sub-microsecond against ~50ms ICE pacing, and in that ordering
        // the orphan holds only the in-window datagrams while USE-CANDIDATE lands on the winner, so
        // the app pins the LIVE tuple.
        if let Some(flow) = flows.get_mut(&src) {
            // Not load-bearing — `reservation` is never moved on this path, so it would drop at
            // end of scope anyway. Explicit so the release is visible next to the fold it pairs
            // with, and so a later edit that DOES move it fails loudly rather than silently leaking
            // a `flow_per_project_max` slot.
            #[allow(clippy::drop_non_drop)]
            drop(reservation);
            flow.last_seen = now;
            flow.bytes_in = flow.bytes_in.saturating_add(n as u64);
            flow.pkts = flow.pkts.saturating_add(1);
            flow.egress.on_ingress(n, amp_k);
            self.plane.note_ingress(base, n, amp_k, now);
            // Read the port's `vm_dst` cache, exactly as the HIT path does — never this datagram's
            // own `live`. The winner may still be mid-boot, and forwarding past it would land ahead
            // of its buffered first packets.
            return match *vm_dst {
                Some(dst) => {
                    self.maybe_promote(flow, base, tenant, now);
                    flow.out_nonce += 1;
                    ReachOutcome::Forward {
                        flow_id: flow.flow_id,
                        epoch: flow.epoch,
                        nonce: flow.out_nonce,
                        dst,
                    }
                }
                None => {
                    self.buffer_push(flow, payload);
                    ReachOutcome::Buffered
                }
            };
        }

        // Resume this client's PREVIOUS identity if we still remember it. The `(flow_id, epoch)`
        // pair is what the agent keys its loopback socket on, so restoring BOTH makes the agent
        // take its existing-flow path (`Decision::Forward`) — same socket, same source port, the
        // app's pinned tuple untouched. A bumped epoch would not do: that is `Decision::Supersede`,
        // which drops the old socket and opens a new one, i.e. exactly the churn we are removing.
        //
        // Restoring an id that may still sit in `quarantine` is deliberate and safe: quarantine
        // guards against a LATE REPLY aliasing an id reused by a DIFFERENT client, and this is the
        // same client resuming — the restored `in_nonce_hw` still rejects anything the old pump
        // already sent. (Keying on `src` inherits the existing assumption that a client is its
        // 5-tuple; a NAT recycling a port onto a different client already attaches to a live flow
        // the same way, and ICE/DTLS reject the mismatch on their own credentials.)
        // A parseable live IP ⇒ warm forward; otherwise (cold, or an unparseable backend) wake.
        let live_dst = live.and_then(|ip| {
            format!("{}:{}", ip, self.spec.agent_udp_port)
                .parse::<SocketAddr>()
                .ok()
        });

        // ONLY on the warm path. A cold boot brings up a NEW agent process with an empty flow map
        // (the agent is the VM's init, so it cannot restart without the VM restarting), and
        // resuming into that would be worse than churn: the agent's fresh pump restarts
        // `out_nonce` at 1 while we hold a high `in_nonce_hw`, blanking the return leg until it
        // climbs back. Scale-to-zero makes that the COMMON path, not a corner — evict, hibernate,
        // client returns — so this guard is load-bearing, not defensive. Snapshot-resume does
        // preserve the agent's state and could safely resume, but the wake path cannot tell a
        // restore from a cold boot here, so it fails safe to a fresh identity.
        let restored = if live_dst.is_some() {
            identity.get_fresh(&src, now).copied()
        } else {
            None
        };
        let (flow_id, epoch) = match restored {
            Some(id) => (id.flow_id, id.epoch),
            None => alloc_flow_id(next_flow_id, epoch_for, *epoch_base),
        };
        let mut flow = Flow::provisional(flow_id, epoch, reservation, now);
        if let Some(id) = restored {
            flow.out_nonce = id.out_nonce;
            identity.remove(&src); // consumed — the identity now lives in `flows` again
        }
        flow.bytes_in = n as u64;
        flow.pkts = 1;

        let outcome = match live_dst {
            Some(dst) => {
                // WARM: forward now. No wake-rate token, no boot. Refresh the cache for HITs.
                *vm_dst = Some(dst);
                flow.out_nonce += 1;
                ReachOutcome::Forward {
                    flow_id,
                    epoch,
                    nonce: flow.out_nonce,
                    dst,
                }
            }
            None if *booting => {
                // COLD, but a boot is already in flight for this port — coalesce (no wake-rate).
                self.buffer_push(&mut flow, payload);
                ReachOutcome::Buffered
            }
            None => {
                // COLD, first MISS for this port since the last boot cleared → the wake gate.
                if !self.plane.try_wake_rate(base, now) {
                    self.plane.count(DropReason::RateCap);
                    return ReachOutcome::Dropped; // `flow` unwinds → reservation released
                }
                self.buffer_push(&mut flow, payload);
                match self.plane.ensure_boot(base, tenant) {
                    BootAdmit::Spawn(guard) => {
                        *booting = true;
                        ReachOutcome::BootSpawn { guard, project_id }
                    }
                    BootAdmit::Coalesced => {
                        *booting = true;
                        self.plane.event(L4Event::WakeCoalesced);
                        ReachOutcome::BootWait { project_id }
                    }
                    BootAdmit::BudgetFull => {
                        self.plane.count(DropReason::BudgetFull);
                        return ReachOutcome::Dropped; // `flow` unwinds → reservation released
                    }
                }
            }
        };
        // Stamp ingress only on the admitted paths (never for a dropped datagram — counting it would
        // wrongly credit the reflection ratio). Then insert.
        flow.egress.on_ingress(n, amp_k);
        self.plane.note_ingress(base, n, amp_k, now);
        flows.insert(src, flow);
        by_flow_id.insert(flow_id, src);
        outcome
    }

    // ---- return loop (guest → edge) ----

    async fn return_loop(self: Arc<Self>) {
        let mut buf = vec![0u8; BUF_SIZE];
        loop {
            let (n, _from) = match self.guest.recv_from(&mut buf).await {
                Ok(v) => v,
                Err(_) => {
                    tokio::time::sleep(Duration::from_millis(1)).await;
                    continue;
                }
            };
            let now = Instant::now();
            // Verify + strip the agent's transit header FIRST (fail-closed). The reply leg is bound
            // to `AgentToHost`, so a host→agent frame replayed back here fails the tag (P0-L4-11).
            let Some((hdr, payload)) = l4_transit::open(
                self.spec.transit_secret.as_bytes(),
                L4Dir::AgentToHost,
                &buf[..n],
            ) else {
                self.plane.count(DropReason::HeaderAuthFail);
                continue;
            };
            if let Some(src) = self.return_decide(hdr, payload, now) {
                let _ = self.edge.send_to(payload, src).await;
            }
        }
    }

    /// The synchronous return-loop decision (holds the port lock; NO `.await`). Returns the client
    /// `src` to reply to, or `None` if dropped (a counter was incremented).
    fn return_decide(
        &self,
        hdr: L4TransitHeader,
        payload: &[u8],
        now: Instant,
    ) -> Option<SocketAddr> {
        let n = payload.len();
        let base = &self.spec.base_project;
        let tenant = self.spec.tenant_id.as_deref();
        let amp_k = self.spec.amp_k;
        let c0_bytes = self.plane.limits().c0_bytes;

        // Kill-switch: a reflection-suspected base's egress is dropped wholesale (§2.5 step 4).
        if self.plane.is_reflection_suspected(base) {
            self.plane.count(DropReason::EgressAmpClamp);
            return None;
        }

        let mut st = self.state.lock().unwrap();
        let PortState {
            flows,
            by_flow_id,
            c0_rate,
            per_source,
            egress: port_egress,
            ..
        } = &mut *st;
        let port_egress = *port_egress;

        // Demux by flow_id → client src. An unknown id is a late reply for a flow the host has
        // evicted — drop, but COUNT it: the frame is authenticated, so a sustained rate here means
        // an agent is still pumping a tuple whose return leg is dead, a silent blackhole for any
        // app that pinned it (#87). Expect a low background rate: any eviction with a reply in
        // flight produces one, and the agent holds its map entry for `host_idle + 60s`. It is the
        // RATE that is diagnostic, not a nonzero value.
        let Some(&src) = by_flow_id.get(&hdr.flow_id) else {
            self.plane.count(DropReason::UnknownFlow);
            return None;
        };
        // `by_flow_id` hit + `flows` miss = the two maps have DESYNCED. That is a host invariant
        // break, not an agent-side symptom: `sweep` removes from both under one lock, so this
        // should be unreachable. Keep it out of `UnknownFlow` — an operator reading that counter as
        // "the agent is pumping a dead tuple" must not have a host bug folded into it.
        let Some(flow) = flows.get_mut(&src) else {
            warn!(
                port = %self.spec.name, flow_id = hdr.flow_id,
                "l4 return: by_flow_id/flows desync — host invariant break, dropping"
            );
            return None;
        };
        if flow.epoch != hdr.epoch {
            self.plane.count(DropReason::StaleEpoch);
            return None;
        }
        // Per-(flow_id,epoch) monotonic-nonce anti-replay (P0-L4-13). Unconditional: a resumed
        // flow carries no high-water forward (see `FlowIdentity`), so this rule needs no exception.
        if hdr.nonce <= flow.in_nonce_hw {
            self.plane.count(DropReason::NonceReplay);
            return None;
        }
        flow.in_nonce_hw = hdr.nonce;
        flow.last_seen = now;

        // ---- Egress controls (Axis 2, §2.5) ----
        // 1. Per-flow ratio credit + one-shot C0 — an OPT-IN per-port shaper (`amp_k` 1..=3).
        //    RETIRED as the default gate (`amp_k == 0`, smarter-limiting arc / W-econ): arbitrary
        //    asymmetric workloads reply freely, bounded instead by the absolute aggregate caps below
        //    + the metered per-tenant egress budget. Only a port that explicitly opts into the
        //    byte-for-byte shaper runs this clamp.
        if amp_k != 0 {
            match flow.egress.try_egress(n, c0_bytes) {
                RatioVerdict::Allowed => {}
                RatioVerdict::Denied => {
                    self.plane.count(DropReason::EgressAmpClamp);
                    return None;
                }
                RatioVerdict::NeedC0 => {
                    // Per-port rate first (local), then the plane's fresh-source + global rate.
                    if !c0_rate.try_take(1.0, now) || !self.plane.try_c0_grant(src.ip(), now) {
                        self.plane.count(DropReason::C0GrantRejected);
                        return None;
                    }
                    flow.egress.commit_c0(n);
                    self.plane.event(L4Event::C0Grant);
                }
            }
        }
        // 2. Per-(port, destination IP) at the PROJECT's resolved rate. Checked here, before the
        //    platform caps, so a tenant that has been given a larger allowance still meets every
        //    platform bound afterwards — the override can only ever be the tighter of the two.
        let (ps_bps, ps_burst) = (
            port_egress.per_source_bps as f64,
            port_egress.per_source_burst as f64,
        );
        //    CHECKED here but not yet debited: if a platform cap below refuses the datagram, this
        //    bucket must not have been charged for something never sent. Otherwise a tenant that
        //    loses the shared global race also burns its own port budget, and its effective rate
        //    falls below the limit it was granted.
        let ok = match per_source
            .get_or_insert_with(src.ip(), now, || TokenBucket::new(ps_bps, ps_burst, now))
        {
            Some(b) => b.can_take(n as f64, now),
            None => false, // map full ⇒ fail-closed, as everywhere else on this path
        };
        if !ok {
            self.plane.count(DropReason::EgressPerSource);
            return None;
        }

        // 3–6. platform victim backstop → per-/24 → per-project → global — ALWAYS enforced
        //    (the workload-agnostic third-party bound that never breaks a legit app).
        //    Lock order is still port → plane: the port lock is held across this synchronous call
        //    and there is no `.await` between, so the commit below cannot interleave.
        if let Err(rej) = self
            .plane
            .try_egress_aggregate(base, src.ip(), n, port_egress, now)
        {
            self.plane.count(match rej {
                EgressReject::PerVictim => DropReason::EgressPerVictim,
                EgressReject::Per24 => DropReason::EgressPer24,
                EgressReject::PerProject => DropReason::EgressPerProject,
                EgressReject::Global => DropReason::EgressGlobal,
            });
            return None;
        }

        // Admitted by every level — NOW debit the port bucket we only checked above, so the whole
        // chain is all-or-nothing. Safe because the port lock has been held throughout and the
        // plane call is synchronous, so nothing could have taken this bucket in between.
        // (`get_or_insert_with` rather than a lookup because it is the only `&mut` accessor; the
        // key was inserted by the check above, so the constructor cannot run here.)
        if let Some(b) =
            per_source.get_or_insert_with(src.ip(), now, || TokenBucket::new(ps_bps, ps_burst, now))
        {
            b.commit(n as f64);
        }

        flow.bytes_out = flow.bytes_out.saturating_add(n as u64);
        flow.pkts = flow.pkts.saturating_add(1);
        self.maybe_promote(flow, base, tenant, now);
        self.plane.note_egress(base, n, amp_k, src.ip(), now);
        Some(src)
    }

    // ---- idle sweep ----

    async fn sweep_loop(self: Arc<Self>) {
        let mut interval = tokio::time::interval(SWEEP_TICK);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            interval.tick().await;
            self.sweep(Instant::now());
        }
    }

    fn sweep(&self, now: Instant) {
        {
            let mut st = self.state.lock().unwrap();
            let PortState {
                flows,
                by_flow_id,
                quarantine,
                epoch_for,
                per_source,
                identity,
                ..
            } = &mut *st;
            // Reclaim expired destination buckets. Without this the map only fills, and a full map
            // is fail-closed — a long-lived port would eventually refuse egress to every client it
            // hadn't already seen.
            per_source.sweep(now);
            identity.sweep(now);
            let mut removed: Vec<(u32, u32)> = Vec::new();
            flows.retain(|src, flow| {
                let timeout = match flow.kind {
                    FlowKind::Provisional => PROVISIONAL_IDLE,
                    FlowKind::Established => self.spec.idle_timeout,
                };
                let keep = now.saturating_duration_since(flow.last_seen) < timeout;
                if !keep {
                    if matches!(flow.kind, FlowKind::Provisional) {
                        self.plane.event(L4Event::ProvisionalExpired);
                    }
                    // Remember who this was, so the client's next datagram RESUMES this flow
                    // instead of minting a new `flow_id` and handing the app a new tuple (#87).
                    // The slot is released either way — this memo holds no reservation, no buffer
                    // and no egress state, so eviction still does its job: a spoof flood cannot
                    // pin a VM warm past its idle window. Overflow (`None`) simply skips the memo
                    // and degrades to the old churn.
                    let ident = FlowIdentity {
                        flow_id: flow.flow_id,
                        epoch: flow.epoch,
                        out_nonce: flow.out_nonce,
                    };
                    if let Some(slot) = identity.get_or_insert_with(*src, now, || ident) {
                        *slot = ident;
                    }
                    removed.push((flow.flow_id, flow.epoch));
                    // `flow` drops here → established_guard then reservation drop → plane decrements.
                }
                keep
            });
            for (fid, ep) in &removed {
                by_flow_id.remove(fid);
                quarantine.push((*fid, *ep, now + REUSE_QUARANTINE));
            }
            quarantine.retain(|(_, _, until)| *until > now);
            // Bound `epoch_for`: keep only active or still-quarantined flow_ids.
            let quarantined: std::collections::HashSet<u32> =
                quarantine.iter().map(|(f, _, _)| *f).collect();
            epoch_for.retain(|fid, _| by_flow_id.contains_key(fid) || quarantined.contains(fid));
        }
        // Reclaim TTL-expired plane aux-map entries (own lock; outside the port lock).
        self.plane.sweep(now);
    }

    // ---- boot / readiness ----

    /// The single-flight boot task: wake the project (bounded by [`BOOT_TIMEOUT`]), then flush the
    /// buffered first packets. Holds the [`WakeInFlight`] guard (permit + inflight marker) for the
    /// boot's whole life — dropped here, releasing it on success, failure, OR timeout.
    async fn boot_task(self: Arc<Self>, guard: WakeInFlight, project_id: String) {
        let woke = tokio::time::timeout(BOOT_TIMEOUT, (self.plane.wake_cb())(project_id)).await;
        match woke {
            Ok(Ok(vm_ip)) => {
                self.plane.event(L4Event::WakeAdmitted);
                self.on_ready(vm_ip).await;
            }
            // Err (timeout) or Ok(Err(WakeError::_)): clear booting; provisional flows expire in 5s.
            _ => self.clear_booting(),
        }
        drop(guard);
    }

    /// A flow coalesced onto a sibling's in-flight boot: poll `resolve_vm_ip` until the VM is up (or
    /// the boot times out), then flush. Holds no permit (the spawning port holds the single one).
    async fn wait_task(self: Arc<Self>, project_id: String) {
        let deadline = Instant::now() + BOOT_TIMEOUT;
        loop {
            if let Some(ip) = (self.resolve_vm_ip)(project_id.clone()).await {
                self.on_ready(ip).await;
                return;
            }
            if Instant::now() >= deadline {
                self.clear_booting();
                return;
            }
            tokio::time::sleep(WAIT_POLL).await;
        }
    }

    /// The VM is up at `vm_ip`: cache `vm_dst` and drain every provisional flow's buffered first
    /// packets. Setting `vm_dst` and draining under the SAME lock closes the race with a concurrent
    /// reach-loop decision — no datagram is buffered after `vm_dst` is set without being flushed.
    async fn on_ready(self: &Arc<Self>, vm_ip: String) {
        let Ok(dst) = format!("{}:{}", vm_ip, self.spec.agent_udp_port).parse::<SocketAddr>()
        else {
            // A vm_ip we can't parse is unusable; unwind cleanly (flows expire, client retransmits).
            self.clear_booting();
            return;
        };
        let jobs: Vec<(u32, u32, u64, Vec<u8>)> = {
            let mut st = self.state.lock().unwrap();
            st.vm_dst = Some(dst);
            st.booting = false;
            // The VM just booted, so the agent is a FRESH process with an empty flow map and reply
            // pumps whose `out_nonce` starts at 1. Every remembered identity is now stale, and
            // resuming one would strand the return leg behind our high `in_nonce_hw`. Drop them
            // all: minting fresh ids is the correct behaviour against a new agent.
            st.identity.clear();
            let mut jobs = Vec::new();
            for flow in st.flows.values_mut() {
                if flow.buffer.is_empty() {
                    continue;
                }
                let bufs = std::mem::take(&mut flow.buffer);
                flow.buffer_bytes = 0;
                for datagram in bufs {
                    flow.out_nonce += 1;
                    jobs.push((flow.flow_id, flow.epoch, flow.out_nonce, datagram));
                }
            }
            jobs
        };
        let mut seal = Vec::with_capacity(BUF_SIZE + l4_transit::L4_HEADER_LEN);
        let secret = self.spec.transit_secret.as_bytes();
        for (flow_id, epoch, nonce, datagram) in jobs {
            l4_transit::seal(
                secret,
                L4Dir::HostToAgent,
                L4TransitHeader {
                    flow_id,
                    epoch,
                    nonce,
                },
                &datagram,
                &mut seal,
            );
            let _ = self.guest.send_to(&seal, dst).await;
        }
    }

    fn clear_booting(&self) {
        self.state.lock().unwrap().booting = false;
    }

    // ---- shared helpers ----

    /// Promote a provisional flow to established once cumulative admitted traffic (EITHER
    /// direction) crosses the thresholds. The ONLY place `conn_count` moves. On a refused
    /// establish (over the tenant's warm fair-share) the flow stays provisional (retried next
    /// datagram). Called while holding the port lock with `flow` borrowed from it.
    fn maybe_promote(&self, flow: &mut Flow, base: &str, tenant: Option<&str>, now: Instant) {
        if flow.kind != FlowKind::Provisional {
            return;
        }
        let bytes = flow.bytes_in.saturating_add(flow.bytes_out);
        let age = now.saturating_duration_since(flow.created);
        if bytes >= MIN_ESTABLISH_BYTES
            && flow.pkts >= MIN_ESTABLISH_PKTS
            && age >= MIN_ESTABLISH_MS
            && let Some(guard) = self.plane.try_establish(base, tenant)
        {
            flow.established_guard = Some(guard);
            flow.kind = FlowKind::Established;
            self.plane.event(L4Event::Promotion);
        }
    }

    fn buffer_push(&self, flow: &mut Flow, payload: &[u8]) {
        let n = payload.len();
        if flow.buffer.len() < REPLAY_MAX_PKTS && flow.buffer_bytes + n <= REPLAY_MAX_BYTES {
            flow.buffer.push(payload.to_vec());
            flow.buffer_bytes += n;
        } else {
            self.plane.count(DropReason::ReplayBufferOverflow);
        }
    }
}

/// Allocate the next per-port `flow_id` (monotonic counter) + its epoch. A FRESH id takes the
/// per-process `epoch_base` (monotonic across restart); a reused id (only after a `2^32` wrap
/// within one process) carries a bumped epoch (P0-L4-13).
fn alloc_flow_id(
    next_flow_id: &mut u32,
    epoch_for: &mut HashMap<u32, u32>,
    epoch_base: u32,
) -> (u32, u32) {
    let fid = *next_flow_id;
    *next_flow_id = next_flow_id.wrapping_add(1);
    let epoch = match epoch_for.get(&fid) {
        Some(e) => e.wrapping_add(1),
        None => epoch_base,
    };
    epoch_for.insert(fid, epoch);
    (fid, epoch)
}

/// Per-process `(epoch_base, flow_id_seed)`. `epoch_base` = wall-clock UNIX seconds (low 32 bits),
/// so across a host-process restart (which always takes ≥1s) it is strictly greater than the
/// previous process's — the agent supersedes rather than drops on a re-adopted VM (P0-L4-13). The
/// `flow_id` seed adds sub-second entropy so even a wall-clock regression across the restart needs
/// a flow_id collision too before an epoch tie could bite. No RNG dependency needed.
fn process_epoch_seed() -> (u32, u32) {
    let d = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default();
    (d.as_secs() as u32, d.subsec_nanos())
}

/// Bind the always-on edge `UdpSocket` on `0.0.0.0:port` with `SO_REUSEADDR` (single-owner rebind
/// ordering across a reconcile) and — deliberately — WITHOUT `SO_REUSEPORT` (design §3(b)).
fn bind_edge_socket(port: u16) -> io::Result<UdpSocket> {
    let sock = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    sock.set_reuse_address(true)?;
    sock.set_nonblocking(true)?;
    let addr: SocketAddr = SocketAddr::from((Ipv4Addr::UNSPECIFIED, port));
    sock.bind(&addr.into())?;
    let std_sock: std::net::UdpSocket = sock.into();
    UdpSocket::from_std(std_sock)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::l4_plane::{L4PlaneLimits, L4PortEgressLimits};
    use crate::{WakeCallback, WakeError};

    fn noop_wake() -> WakeCallback {
        Arc::new(|_p: String| {
            Box::pin(async { Err(WakeError::Unavailable("test".into())) })
                as Pin<Box<dyn Future<Output = _> + Send>>
        })
    }

    /// A port whose backend always resolves WARM.
    async fn warm_port() -> Arc<L4Ingress> {
        port_with(Arc::new(|_p: String| {
            Box::pin(async { Some("10.0.0.2".to_string()) }) as _
        }))
        .await
    }

    /// A port whose backend never resolves — every admit takes the cold/wake path.
    async fn cold_port() -> Arc<L4Ingress> {
        port_with(Arc::new(|_p: String| Box::pin(async { None }) as _)).await
    }

    async fn port_with(resolve: ResolveVmIp) -> Arc<L4Ingress> {
        let spec = L4PortSpec {
            project_id: "p".into(),
            base_project: "p".into(),
            tenant_id: Some("t".into()),
            name: "media".into(),
            proto: "udp".into(),
            external_port: 0, // ephemeral: the test never sends on the edge
            agent_udp_port: 4000,
            guest_port: 21093,
            idle_timeout: Duration::from_secs(120),
            amp_k: 0,
            transit_secret: "secret".into(),
            egress: L4PortEgressLimits {
                per_source_bps: 1024 * 1024,
                per_source_burst: 64 * 1024,
                per_project_bps: 16 * 1024 * 1024,
            },
        };
        let plane = L4Plane::new(
            L4PlaneLimits {
                host_ram_reserve_mib: 0,
                ..Default::default()
            },
            noop_wake(),
        );
        L4Ingress::bind(spec, plane, resolve, CancellationToken::new())
            .await
            .expect("bind")
    }

    /// `reach_admit` must fold a second MISS for one `src` into the existing flow rather than mint
    /// a second `flow_id`. `reach_loop` is single-task and CANNOT produce this interleaving, so the
    /// test calls `reach_decide`/`reach_admit` directly to manufacture it: it guards the invariant
    /// for a future parallelised reach loop. It is not a reproduction of #87.
    #[tokio::test]
    async fn concurrent_miss_for_one_src_folds_into_a_single_flow() {
        let port = warm_port().await;
        let src: SocketAddr = "203.0.113.7:40000".parse().unwrap();
        let now = Instant::now();
        let payload = b"stun-binding-request";

        // Two MISSes race: neither has been admitted yet, so both reserve a slot.
        let first = port.reach_decide(src, payload, now);
        let second = port.reach_decide(src, payload, now);
        let (ReachOutcome::CheckLiveness { reservation: r1, .. }, 
             ReachOutcome::CheckLiveness { reservation: r2, .. }) = (first, second)
        else {
            panic!("both datagrams should MISS while nothing is inserted");
        };

        // Both resolves come back WARM and admit, in order.
        let a = port.reach_admit(src, payload, now, r1, "p".into(), Some("10.0.0.2".into()));
        let b = port.reach_admit(src, payload, now, r2, "p".into(), Some("10.0.0.2".into()));

        let (ReachOutcome::Forward { flow_id: fa, epoch: ea, nonce: na, .. }, 
             ReachOutcome::Forward { flow_id: fb, epoch: eb, nonce: nb, .. }) = (a, b)
        else {
            panic!("a warm admit forwards");
        };

        // One flow, one agent loopback socket, one tuple toward the guest app.
        assert_eq!(fa, fb, "the racing datagram must not mint a second flow_id");
        assert_eq!(ea, eb);
        // ...and the host→agent nonce stays strictly monotonic on it.
        assert_eq!((na, nb), (1, 2));

        // The duplicate slot must be RELEASED, not leaked — no public gauge shows this, since
        // `conn_count` counts only ESTABLISHED flows.
        assert_eq!(
            port.plane.flow_count_for_test("p"),
            1,
            "the folded datagram's reservation must be released"
        );

        let st = port.state.lock().unwrap();
        assert_eq!(st.flows.len(), 1, "one client src ⇒ one flow");
        assert_eq!(
            st.by_flow_id.len(),
            1,
            "an orphaned by_flow_id entry is the leak that strands the agent's socket"
        );
        assert_eq!(st.by_flow_id.get(&fa), Some(&src));
        // The folded datagram was accounted, not dropped.
        assert_eq!(st.flows[&src].pkts, 2);
        assert_eq!(st.flows[&src].bytes_in, 2 * payload.len() as u64);
    }

    /// An evicted client that comes back inside [`IDENTITY_MEMO_TTL`] must RESUME its flow, not
    /// mint a new one: the agent opens a loopback socket per `flow_id`, so a new id hands a live
    /// app a new remote tuple. mediasoup, once ICE is COMPLETED, stores such a tuple for receive
    /// but never selects it, so DTLS keeps going to the dead one forever (#87).
    #[tokio::test]
    async fn an_evicted_client_resumes_its_flow_identity() {
        let port = warm_port().await;
        let src: SocketAddr = "203.0.113.20:41010".parse().unwrap();
        let t0 = Instant::now();

        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", t0)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id: first, epoch: e1, nonce: n1, .. } =
            port.reach_admit(src, b"x", t0, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        // A reply lands, so the return-leg high-water is non-zero and must survive too.
        let hdr = L4TransitHeader { flow_id: first, epoch: e1, nonce: 7 };
        assert_eq!(port.return_decide(hdr, b"reply", t0), Some(src));

        // Idle past PROVISIONAL_IDLE (the flow never promoted — far under 1024 B / 3 pkts).
        let later = t0 + Duration::from_secs(6);
        port.sweep(later);
        assert_eq!(port.state.lock().unwrap().flows.len(), 0, "swept");

        // The client returns.
        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"y", later)
        else { panic!("re-MISS") };
        let ReachOutcome::Forward { flow_id: second, epoch: e2, nonce: n2, .. } =
            port.reach_admit(src, b"y", later, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        assert_eq!((second, e2), (first, e1), "identity must be RESUMED, not re-minted");
        assert!(n2 > n1, "forward nonce must keep climbing for the agent's high-water: {n1} -> {n2}");

        // The return-leg high-water is deliberately NOT carried across (see `FlowIdentity`), so a
        // pre-eviction nonce is admitted once into the resumed incarnation. That is the priced
        // trade: replaying it needs bridge capture and delivers a duplicate the app discards,
        // whereas carrying the high-water forward would blank the return leg outright whenever the
        // agent has moved on — which the host cannot detect.
        let stale = L4TransitHeader { flow_id: first, epoch: e1, nonce: 7 };
        assert_eq!(port.return_decide(stale, b"reply", later), Some(src));
        // Monotonicity is enforced from there.
        let stale = L4TransitHeader { flow_id: first, epoch: e1, nonce: 7 };
        assert!(port.return_decide(stale, b"reply", later).is_none());
        assert_eq!(port.plane.drain_counters().nonce_replay, 1);
    }

    /// The safety property the whole design rests on: a resumed flow carries NO return-leg
    /// high-water, so it behaves exactly like a fresh flow toward whatever agent it lands on.
    /// That is what makes resuming safe when the agent has moved on beneath us — a wake this port
    /// did not drive, an agent LRU eviction on a warm VM, a host restart — none of which the host
    /// can detect.
    #[tokio::test]
    async fn a_resumed_flow_carries_no_return_leg_high_water() {
        let port = warm_port().await;
        let src: SocketAddr = "203.0.113.24:41014".parse().unwrap();
        let t0 = Instant::now();

        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", t0)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id, epoch, nonce: fwd, .. } =
            port.reach_admit(src, b"x", t0, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };
        // Drive the high-water up, as a live media flow would.
        for n in 1..=40 {
            let h = L4TransitHeader { flow_id, epoch, nonce: n };
            assert_eq!(port.return_decide(h, b"r", t0), Some(src));
        }

        let later = t0 + Duration::from_secs(6);
        port.sweep(later);
        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"y", later)
        else { panic!("re-MISS") };
        let ReachOutcome::Forward { flow_id: f2, epoch: e2, nonce: fwd2, .. } =
            port.reach_admit(src, b"y", later, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };
        assert_eq!((f2, e2), (flow_id, epoch), "identity resumed");
        // The FORWARD counter must keep climbing — a live agent's high-water is still up there.
        assert!(fwd2 > fwd, "forward nonce must resume: {fwd} -> {fwd2}");
        let _ = port.plane.drain_counters();

        // A brand-new agent pump, restarting at 1, is admitted immediately — no wall to climb.
        let h = L4TransitHeader { flow_id, epoch, nonce: 1 };
        assert_eq!(
            port.return_decide(h, b"r", later),
            Some(src),
            "a resumed flow must accept a fresh pump's first datagram"
        );
        // ...and monotonicity is enforced again from there.
        let h = L4TransitHeader { flow_id, epoch, nonce: 1 };
        assert!(port.return_decide(h, b"r", later).is_none());
        assert_eq!(port.plane.drain_counters().nonce_replay, 1);
    }

    /// A COLD admit must never resume: the boot brings up a fresh agent whose reply pumps restart
    /// `out_nonce` at 1, so resuming our high `in_nonce_hw` would blank the return leg. Scale-to-
    /// zero makes evict -> hibernate -> client-returns the common path, so this is load-bearing.
    #[tokio::test]
    async fn a_cold_admit_never_resumes_a_remembered_identity() {
        let port = warm_port().await;
        let src: SocketAddr = "203.0.113.22:41012".parse().unwrap();
        let t0 = Instant::now();

        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", t0)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id: first, .. } =
            port.reach_admit(src, b"x", t0, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        let later = t0 + Duration::from_secs(6);
        port.sweep(later);

        // The client returns while the VM is COLD (`live = None`) — the wake path.
        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"y", later)
        else { panic!("re-MISS") };
        let out = port.reach_admit(src, b"y", later, reservation, "p".into(), None);
        assert!(matches!(out, ReachOutcome::BootSpawn { .. }), "cold ⇒ wake");
        let st = port.state.lock().unwrap();
        assert_ne!(
            st.flows[&src].flow_id, first,
            "a cold admit must mint a FRESH identity — the agent it will reach is new"
        );
    }

    /// A completed boot invalidates every remembered identity on the port: the agent is a new
    /// process with an empty flow map, so nothing may be resumed into it.
    #[tokio::test]
    async fn a_completed_boot_clears_every_remembered_identity() {
        let port = cold_port().await;
        let src: SocketAddr = "203.0.113.23:41013".parse().unwrap();
        let t0 = Instant::now();

        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", t0)
        else { panic!("MISS") };
        let _ = port.reach_admit(src, b"x", t0, reservation, "p".into(), Some("10.0.0.2".into()));
        let later = t0 + Duration::from_secs(6);
        port.sweep(later);
        assert!(
            port.state.lock().unwrap().identity.contains(&src),
            "eviction should have remembered it"
        );

        port.on_ready("10.0.0.2".into()).await;
        assert!(
            !port.state.lock().unwrap().identity.contains(&src),
            "a fresh agent invalidates every memo"
        );
    }

    /// The memo must not outlive the AGENT's flow entry. Past its TTL the client gets a fresh
    /// identity, because the agent will have opened a fresh socket too — resuming a nonce
    /// high-water the agent has forgotten would blank the return leg instead of fixing it.
    #[tokio::test]
    async fn a_long_gone_client_gets_a_fresh_identity() {
        let port = warm_port().await;
        let src: SocketAddr = "203.0.113.21:41011".parse().unwrap();
        let t0 = Instant::now();

        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", t0)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id: first, .. } =
            port.reach_admit(src, b"x", t0, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        port.sweep(t0 + Duration::from_secs(6));
        let way_later = t0 + IDENTITY_MEMO_TTL + Duration::from_secs(30);
        let ReachOutcome::CheckLiveness { reservation, .. } =
            port.reach_decide(src, b"y", way_later)
        else { panic!("re-MISS") };
        let ReachOutcome::Forward { flow_id: second, nonce, .. } =
            port.reach_admit(src, b"y", way_later, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        assert_ne!(second, first, "past the TTL the identity must NOT be resumed");
        assert_eq!(nonce, 1, "a fresh identity restarts the forward nonce");
    }

    /// First coverage of the return leg. An authenticated reply whose `flow_id` the host no longer
    /// holds must drop AND count — before this it bailed on a bare `?`, incrementing nothing, which
    /// is why the counters could neither confirm nor kill #87's hypothesis.
    #[tokio::test]
    async fn return_leg_counts_a_reply_for_an_unknown_flow() {
        let port = warm_port().await;
        let now = Instant::now();

        // A live flow, so the miss below is about the id and not an empty table.
        let src: SocketAddr = "203.0.113.10:40002".parse().unwrap();
        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", now)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id, epoch, .. } =
            port.reach_admit(src, b"x", now, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };
        let _ = port.plane.drain_counters(); // zero the window

        // A reply for an id the host never issued: the shape a stranded agent socket produces.
        let hdr = L4TransitHeader { flow_id: flow_id.wrapping_add(9_999), epoch, nonce: 1 };
        assert!(port.return_decide(hdr, b"reply", now).is_none());
        assert_eq!(port.plane.drain_counters().unknown_flow, 1);

        // The live flow's own reply still passes, and comes back addressed to its client.
        let hdr = L4TransitHeader { flow_id, epoch, nonce: 1 };
        assert_eq!(port.return_decide(hdr, b"reply", now), Some(src));
        let c = port.plane.drain_counters();
        assert_eq!((c.unknown_flow, c.stale_epoch, c.nonce_replay), (0, 0, 0));
    }

    /// The return leg's two anti-replay gates, which had no coverage either.
    #[tokio::test]
    async fn return_leg_rejects_a_stale_epoch_and_a_replayed_nonce() {
        let port = warm_port().await;
        let now = Instant::now();
        let src: SocketAddr = "203.0.113.11:40003".parse().unwrap();
        let ReachOutcome::CheckLiveness { reservation, .. } = port.reach_decide(src, b"x", now)
        else { panic!("MISS") };
        let ReachOutcome::Forward { flow_id, epoch, .. } =
            port.reach_admit(src, b"x", now, reservation, "p".into(), Some("10.0.0.2".into()))
        else { panic!("warm forward") };

        // Right id, wrong epoch — a reply for a PRIOR owner of this id.
        let stale = L4TransitHeader { flow_id, epoch: epoch.wrapping_sub(1), nonce: 1 };
        assert!(port.return_decide(stale, b"reply", now).is_none());
        assert_eq!(port.plane.drain_counters().stale_epoch, 1);

        // Nonce must strictly exceed the high-water: 5 admits, then 5 and 4 are replays.
        let hdr = L4TransitHeader { flow_id, epoch, nonce: 5 };
        assert!(port.return_decide(hdr, b"reply", now).is_some());
        for n in [5u64, 4] {
            let h = L4TransitHeader { flow_id, epoch, nonce: n };
            assert!(port.return_decide(h, b"reply", now).is_none());
        }
        assert_eq!(port.plane.drain_counters().nonce_replay, 2);
    }

    /// The fold reads the PORT's `vm_dst`, never the racing datagram's own `live`. A winner still
    /// mid-boot has `vm_dst = None` and buffered first packets; forwarding the racer on its own
    /// freshly-resolved ip would land it AHEAD of them, reordering the flow's opening bytes.
    #[tokio::test]
    async fn fold_buffers_behind_a_winner_that_is_still_booting() {
        let port = cold_port().await;
        let src: SocketAddr = "203.0.113.8:40001".parse().unwrap();
        let now = Instant::now();
        let payload = b"first";

        let (
            ReachOutcome::CheckLiveness { reservation: r1, .. },
            ReachOutcome::CheckLiveness { reservation: r2, .. },
        ) = (
            port.reach_decide(src, payload, now),
            port.reach_decide(src, payload, now),
        ) else {
            panic!("both MISS")
        };

        // Winner resolves COLD: takes the wake gate, buffers, leaves `vm_dst = None`.
        let a = port.reach_admit(src, payload, now, r1, "p".into(), None);
        assert!(matches!(a, ReachOutcome::BootSpawn { .. }), "winner drives the boot");

        // The racer's OWN resolve came back warm — it must still buffer behind the winner.
        let b = port.reach_admit(src, payload, now, r2, "p".into(), Some("10.0.0.2".into()));
        assert!(
            matches!(b, ReachOutcome::Buffered),
            "the fold must honour the port's vm_dst, not the racer's own live resolve"
        );
        assert_eq!(port.state.lock().unwrap().flows.len(), 1);
    }

    #[test]
    fn fresh_flow_id_takes_epoch_base_and_bumps_on_reuse() {
        // "Prior process": flow_ids 0,1 allocated at a LOW epoch base.
        let mut next = 0u32;
        let mut epoch_for = HashMap::new();
        assert_eq!(alloc_flow_id(&mut next, &mut epoch_for, 100), (0, 100));
        assert_eq!(alloc_flow_id(&mut next, &mut epoch_for, 100), (1, 100));

        // A reused flow_id (only after a 2^32 wrap in one run) bumps strictly ABOVE the run's
        // fresh epoch — never colliding with a live entry for the same id.
        let mut reuse_next = 0u32; // points back at flow_id 0, which is already in `epoch_for`
        let (fid, epoch) = alloc_flow_id(&mut reuse_next, &mut epoch_for, 100);
        assert_eq!((fid, epoch), (0, 101));
    }

    #[test]
    fn post_restart_higher_epoch_base_supersedes_same_flow_id() {
        // A re-adopted VM's agent still holds (flow_id=0, epoch=100) after a host-process restart.
        let (_f_old, epoch_old) = alloc_flow_id(&mut 0u32, &mut HashMap::new(), 100);
        // The restarted process re-seeds a STRICTLY GREATER epoch base (wall-clock advanced) and
        // its flow_id counter reset to 0 → it reuses flow_id 0.
        let (f_new, epoch_new) = alloc_flow_id(&mut 0u32, &mut HashMap::new(), 200);
        assert_eq!(f_new, 0);
        // The agent's `epoch > stored ⇒ supersede` path fires (fresh loopback socket + hw reset),
        // so the reconnecting client is NOT dropped until the stale entry idle-evicts.
        assert!(
            epoch_new > epoch_old,
            "post-restart epoch must exceed the prior epoch for the same flow_id"
        );
    }

    #[test]
    fn process_epoch_seed_is_a_plausible_wall_clock_second() {
        let (base, _seed) = process_epoch_seed();
        // Wall-clock seconds since 1970 — comfortably nonzero on any real host (after ~2023), and
        // below u32::MAX (no truncation wrap until 2106), so it stays monotonic across restarts.
        assert!(base > 1_700_000_000);
    }
}
