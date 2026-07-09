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

use crate::l4_egress::{RatioCredit, RatioVerdict, TokenBucket};
use crate::l4_plane::{
    BootAdmit, DropReason, EgressReject, L4Event, L4FlowGuard, L4Plane, ReserveReject,
    WakeInFlight, FlowReservation,
};
use jkbase_common::l4_transit::{self, L4Dir, L4TransitHeader};
use socket2::{Domain, Protocol, Socket, Type};
use std::collections::HashMap;
use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, SocketAddr};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use tokio::net::UdpSocket;
use tokio_util::sync::CancellationToken;

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
    /// The resolved `vm_ip:agent_udp_port`; `None` until a boot proves readiness.
    vm_dst: Option<SocketAddr>,
    /// A boot task is running for this port (single-flight of the boot/flush per port).
    booting: bool,
    /// Per-port one-shot C0-grant rate limiter.
    c0_rate: TokenBucket,
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
            vm_dst: None,
            booting: false,
            c0_rate: TokenBucket::new(C0_PER_PORT_RATE, C0_PER_PORT_BURST, now),
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
    fn reach_decide(self: &Arc<Self>, src: SocketAddr, payload: &[u8], now: Instant) -> ReachOutcome {
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
            ..
        } = &mut *st;

        let (flow_id, epoch) = alloc_flow_id(next_flow_id, epoch_for, *epoch_base);
        let mut flow = Flow::provisional(flow_id, epoch, reservation, now);
        flow.bytes_in = n as u64;
        flow.pkts = 1;

        // A parseable live IP ⇒ warm forward; otherwise (cold, or an unparseable backend) wake.
        let live_dst = live.and_then(|ip| {
            format!("{}:{}", ip, self.spec.agent_udp_port)
                .parse::<SocketAddr>()
                .ok()
        });

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
            ..
        } = &mut *st;

        // Demux by flow_id → client src. An unknown id is a late reply for an evicted flow — drop.
        let src = *by_flow_id.get(&hdr.flow_id)?;
        let flow = flows.get_mut(&src)?;
        if flow.epoch != hdr.epoch {
            self.plane.count(DropReason::StaleEpoch);
            return None;
        }
        // Per-(flow_id,epoch) monotonic-nonce anti-replay (P0-L4-13).
        if hdr.nonce <= flow.in_nonce_hw {
            self.plane.count(DropReason::NonceReplay);
            return None;
        }
        flow.in_nonce_hw = hdr.nonce;
        flow.last_seen = now;

        // ---- Egress controls (Axis 2, §2.5) ----
        // 1. per-flow ratio credit + one-shot C0.
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
        // 2–5. per-source(IP) → per-/24 → per-project → global aggregate caps.
        if let Err(rej) = self.plane.try_egress_aggregate(base, src.ip(), n, now) {
            self.plane.count(match rej {
                EgressReject::PerSource => DropReason::EgressPerSource,
                EgressReject::Per24 => DropReason::EgressPer24,
                EgressReject::PerProject => DropReason::EgressPerProject,
                EgressReject::Global => DropReason::EgressGlobal,
            });
            return None;
        }

        // Admitted.
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
                ..
            } = &mut *st;
            let mut removed: Vec<(u32, u32)> = Vec::new();
            flows.retain(|_src, flow| {
                let timeout = match flow.kind {
                    FlowKind::Provisional => PROVISIONAL_IDLE,
                    FlowKind::Established => self.spec.idle_timeout,
                };
                let keep = now.saturating_duration_since(flow.last_seen) < timeout;
                if !keep {
                    if matches!(flow.kind, FlowKind::Provisional) {
                        self.plane.event(L4Event::ProvisionalExpired);
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
        let Ok(dst) = format!("{}:{}", vm_ip, self.spec.agent_udp_port).parse::<SocketAddr>() else {
            // A vm_ip we can't parse is unusable; unwind cleanly (flows expire, client retransmits).
            self.clear_booting();
            return;
        };
        let jobs: Vec<(u32, u32, u64, Vec<u8>)> = {
            let mut st = self.state.lock().unwrap();
            st.vm_dst = Some(dst);
            st.booting = false;
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
        if bytes >= MIN_ESTABLISH_BYTES && flow.pkts >= MIN_ESTABLISH_PKTS && age >= MIN_ESTABLISH_MS
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
