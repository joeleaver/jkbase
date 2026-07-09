//! `L4Plane` — the **plane-global** controller shared by every port's [`crate::l4_ingress::L4Ingress`]
//! and read by the server's idle/metering loops. It owns the cross-port state the two abuse axes
//! of the L4 UDP design need bounded (design §3(c), P0-L4-2 / P0-L4-6 / P0-L4-5):
//!
//! - **Axis 1 (cost-DoS).** A per-**base-project** wake-rate token bucket, a UDP-plane-private
//!   global concurrent-wake `Semaphore` with a **per-tenant fair-share**, single-flight of the
//!   permit (exactly one per in-flight boot), a **global distinct-warm-project ceiling** + a
//!   host-RAM floor read from `/proc/meminfo`, and the two-phase flow **reservation** (provisional,
//!   does NOT touch `conn_count`) → **promotion** (established, the only place `conn_count` moves).
//!   Every gate is keyed on `base_project` / tenant — **never on the spoofable source IP**.
//! - **Axis 2 (reflection).** The per-project / per-/24 / global egress token buckets, the global
//!   C0-grant rate, the per-source(IP) bucket + fresh-source C0 tracking, and the automatic
//!   reflection kill-switch (sustained egress:ingress ratio or destination-entropy spike →
//!   `reflection_suspected`). Per-source keying lives HERE, keyed on the reply **destination IP**
//!   (design §3(c): worthless on the wake axis, decisive on the egress axis).
//!
//! Concurrency: the plane is fail-closed and holds **at most one** of its internal mutexes at a
//! time (never nested), and the pump always locks its own per-port state *before* any plane mutex,
//! so the global lock order is `port → plane` with no cycle. All aux maps are cardinality-bounded
//! + TTL-evicted, fail-closed on overflow ([`crate::l4_egress::BoundedTtlMap`], P0-L4-5/-9).

use crate::WakeCallback;
use crate::l4_egress::{BoundedTtlMap, TokenBucket};
use std::collections::{HashMap, HashSet};
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};
use tracing::warn;

// ---- host constants (NOT tenant-tunable; design §6) --------------------------------------------

/// Sliding evaluation window for the reflection kill-switch.
const REFLECTION_WINDOW: Duration = Duration::from_secs(10);
/// Egress floor (bytes/window) below which a base is never flagged — tiny flows can't reflect.
const REFLECTION_MIN_EGRESS: u64 = 256 * 1024;
/// Slack (bytes/window) added to the `amp_k × ingress` ceiling before flagging, absorbing the
/// legitimate one-shot C0 grants so a normal request/reply app never trips.
const REFLECTION_SLACK_BYTES: u64 = 32 * 1024;
/// Distinct reply-destinations in one window above which a base is flagged (spray signature).
const REFLECTION_DEST_ENTROPY: usize = 64;
/// Hard cap on the per-base destination set (a spray past this counts as entropy-exceeded).
const DEST_SET_CAP: usize = 128;

/// TTL / cardinality bounds for the plane's aux maps (all fail-closed on overflow).
const WAKE_RATE_MAP_MAX: usize = 8192;
const WAKE_RATE_TTL: Duration = Duration::from_secs(300);
const PER_PROJECT_MAP_MAX: usize = 8192;
const PER_PROJECT_TTL: Duration = Duration::from_secs(600);
const PER_24_TTL: Duration = Duration::from_secs(120);
const PER_SOURCE_TTL: Duration = Duration::from_secs(120);
const C0_SOURCE_TTL: Duration = Duration::from_secs(300);
const ACTIVITY_MAP_MAX: usize = 8192;
const ACTIVITY_TTL: Duration = Duration::from_secs(900);
const REFL_MAP_MAX: usize = 8192;
const REFL_TTL: Duration = Duration::from_secs(60);
/// Re-read `/proc/meminfo` at most this often (the RAM floor tolerates second-scale staleness).
const MEM_CACHE_TTL: Duration = Duration::from_secs(1);

/// Tunable plane-global limits. The server builds these from constants/config; every field has a
/// sane default so a bare `L4PlaneLimits::default()` is safe.
#[derive(Clone, Debug)]
pub struct L4PlaneLimits {
    /// Per-base-project wake token-bucket burst.
    pub wake_rate_burst: u32,
    /// Per-base-project wake refill (tokens/sec).
    pub wake_rate_refill_per_sec: f64,
    /// Global concurrent-wake permits (UDP-plane-private; never shared with HTTP/DB).
    pub wake_budget: usize,
    /// Max concurrent in-flight wakes attributable to ONE tenant (fair-share of `wake_budget`).
    pub wake_fair_share: usize,
    /// Max distinct base-projects UDP-warm at once (global ceiling).
    pub global_warm_ceiling: usize,
    /// `/proc/meminfo` MemAvailable floor (MiB) the UDP plane refuses to dip a new warm VM below.
    pub host_ram_reserve_mib: u64,
    /// Flow-table entries per base-project.
    pub flow_per_project_max: usize,
    /// Flow-table entries across all ports.
    pub flow_global_max: usize,
    /// Max global flow entries for one tenant (fair-share of `flow_global_max`).
    pub flow_global_fair_share: usize,
    /// Per-project egress ceiling (bytes/sec).
    pub egress_per_project_bps: u64,
    /// Per-destination-/24 egress backstop (bytes/sec).
    pub egress_per_24_bps: u64,
    /// Global platform egress ceiling (bytes/sec).
    pub egress_global_bps: u64,
    /// One-shot C0 floor per fresh source (bytes).
    pub c0_bytes: u64,
    /// Global C0-grant rate (grants/sec).
    pub c0_grant_per_sec_global: f64,
    /// Per-source(IP) egress rate (bytes/sec).
    pub per_source_bps: u64,
    /// Per-source(IP) egress burst (bytes).
    pub per_source_burst: u64,
    /// Per-source aux-map cardinality bound.
    pub source_map_max: usize,
}

impl Default for L4PlaneLimits {
    fn default() -> Self {
        Self {
            wake_rate_burst: 5,
            wake_rate_refill_per_sec: 0.5, // 1 per 2s sustained
            wake_budget: 16,
            wake_fair_share: 4,
            global_warm_ceiling: 32,
            host_ram_reserve_mib: 512,
            flow_per_project_max: 256,
            flow_global_max: 4096,
            flow_global_fair_share: 512,
            egress_per_project_bps: 16 * 1024 * 1024,
            egress_per_24_bps: 8 * 1024 * 1024,
            egress_global_bps: 64 * 1024 * 1024,
            c0_bytes: 1500,
            c0_grant_per_sec_global: 500.0,
            per_source_bps: 1024 * 1024,
            per_source_burst: 64 * 1024,
            source_map_max: 65536,
        }
    }
}

/// Snapshot of the per-reason drop counters + event counters + gauges (design §5). Returned by
/// [`L4Plane::drain_counters`] each metering tick (read-and-reset).
#[derive(Default, Clone, Debug)]
pub struct L4Counters {
    // ---- drop reasons ----
    pub rate_cap: u64,
    pub budget_full: u64,
    pub warm_full_global: u64,
    pub flow_full_project: u64,
    pub flow_full_global: u64,
    pub agent_map_full: u64,
    pub unknown_port: u64,
    pub header_auth_fail: u64,
    pub nonce_replay: u64,
    pub stale_epoch: u64,
    pub egress_amp_clamp: u64,
    pub egress_per_source: u64,
    pub egress_per_project: u64,
    pub egress_per_24: u64,
    pub egress_global: u64,
    pub c0_grant_rejected: u64,
    pub replay_buffer_overflow: u64,
    pub udp_readiness_timeout: u64,
    pub edge_bind_eaddrinuse: u64,
    // ---- events ----
    pub wakes_admitted: u64,
    pub wakes_coalesced: u64,
    pub promotions: u64,
    pub provisional_expired: u64,
    pub c0_grants: u64,
}

/// The proxy-side counters the pump increments. Agent-side reasons (`agent_map_full`,
/// `udp_readiness_timeout`) are in [`L4Counters`] for the server's unified view but are not set here.
#[derive(Debug, Clone, Copy)]
pub(crate) enum DropReason {
    RateCap,
    BudgetFull,
    WarmFullGlobal,
    FlowFullProject,
    FlowFullGlobal,
    HeaderAuthFail,
    NonceReplay,
    StaleEpoch,
    EgressAmpClamp,
    EgressPerSource,
    EgressPerProject,
    EgressPer24,
    EgressGlobal,
    C0GrantRejected,
    ReplayBufferOverflow,
    EdgeBindEaddrinuse,
}

#[derive(Debug, Clone, Copy)]
pub(crate) enum L4Event {
    WakeAdmitted,
    WakeCoalesced,
    Promotion,
    ProvisionalExpired,
    C0Grant,
}

/// Atomic mirror of [`L4Counters`], incremented lock-free on the hot path.
#[derive(Default)]
struct AtomicCounters {
    rate_cap: AtomicU64,
    budget_full: AtomicU64,
    warm_full_global: AtomicU64,
    flow_full_project: AtomicU64,
    flow_full_global: AtomicU64,
    header_auth_fail: AtomicU64,
    nonce_replay: AtomicU64,
    stale_epoch: AtomicU64,
    egress_amp_clamp: AtomicU64,
    egress_per_source: AtomicU64,
    egress_per_project: AtomicU64,
    egress_per_24: AtomicU64,
    egress_global: AtomicU64,
    c0_grant_rejected: AtomicU64,
    replay_buffer_overflow: AtomicU64,
    edge_bind_eaddrinuse: AtomicU64,
    wakes_admitted: AtomicU64,
    wakes_coalesced: AtomicU64,
    promotions: AtomicU64,
    provisional_expired: AtomicU64,
    c0_grants: AtomicU64,
}

impl AtomicCounters {
    fn drain(&self) -> L4Counters {
        L4Counters {
            rate_cap: self.rate_cap.swap(0, Ordering::Relaxed),
            budget_full: self.budget_full.swap(0, Ordering::Relaxed),
            warm_full_global: self.warm_full_global.swap(0, Ordering::Relaxed),
            flow_full_project: self.flow_full_project.swap(0, Ordering::Relaxed),
            flow_full_global: self.flow_full_global.swap(0, Ordering::Relaxed),
            agent_map_full: 0,
            unknown_port: 0,
            header_auth_fail: self.header_auth_fail.swap(0, Ordering::Relaxed),
            nonce_replay: self.nonce_replay.swap(0, Ordering::Relaxed),
            stale_epoch: self.stale_epoch.swap(0, Ordering::Relaxed),
            egress_amp_clamp: self.egress_amp_clamp.swap(0, Ordering::Relaxed),
            egress_per_source: self.egress_per_source.swap(0, Ordering::Relaxed),
            egress_per_project: self.egress_per_project.swap(0, Ordering::Relaxed),
            egress_per_24: self.egress_per_24.swap(0, Ordering::Relaxed),
            egress_global: self.egress_global.swap(0, Ordering::Relaxed),
            c0_grant_rejected: self.c0_grant_rejected.swap(0, Ordering::Relaxed),
            replay_buffer_overflow: self.replay_buffer_overflow.swap(0, Ordering::Relaxed),
            udp_readiness_timeout: 0,
            edge_bind_eaddrinuse: self.edge_bind_eaddrinuse.swap(0, Ordering::Relaxed),
            wakes_admitted: self.wakes_admitted.swap(0, Ordering::Relaxed),
            wakes_coalesced: self.wakes_coalesced.swap(0, Ordering::Relaxed),
            promotions: self.promotions.swap(0, Ordering::Relaxed),
            provisional_expired: self.provisional_expired.swap(0, Ordering::Relaxed),
            c0_grants: self.c0_grants.swap(0, Ordering::Relaxed),
        }
    }
}

// ---- flow accounting --------------------------------------------------------------------------

/// Per-base flow accounting. `total` = provisional + established (the flow-table + warm-set
/// dimension); `established` = the `conn_count` gauge (only promoted flows).
#[derive(Default)]
struct BaseFlows {
    total: usize,
    established: usize,
}

#[derive(Default)]
struct FlowState {
    by_base: HashMap<String, BaseFlows>,
    global_total: usize,
    tenant_total: HashMap<String, usize>,
    /// Distinct base-projects a tenant holds ESTABLISHED (the per-tenant warm fair-share gauge).
    tenant_established: HashMap<String, HashSet<String>>,
}

/// Why [`L4Plane::try_reserve_flow`] refused a provisional flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ReserveReject {
    /// Per-base flow-table cap hit.
    Project,
    /// Global flow-table cap OR this tenant's global fair-share hit.
    Global,
    /// Global distinct-warm-project ceiling hit (this base isn't warm yet).
    WarmCeiling,
    /// Host-RAM floor would be breached by warming a new base.
    Ram,
}

// ---- wake gate --------------------------------------------------------------------------------

struct WakeState {
    /// Per-base wake token buckets.
    wake_rate: BoundedTtlMap<String, TokenBucket>,
    /// Base-projects with a boot currently in flight → owning tenant (single-flight key).
    inflight: HashMap<String, Option<String>>,
    /// Concurrent in-flight wakes attributed to each tenant (fair-share gauge).
    tenant_inflight: HashMap<String, usize>,
}

/// Outcome of [`L4Plane::ensure_boot`].
pub(crate) enum BootAdmit {
    /// Caller must SPAWN the boot task and hold this guard for the boot's life (it holds the
    /// single global permit + the inflight/tenant markers, released on drop).
    Spawn(WakeInFlight),
    /// A boot for this base is already in flight (single-flight) — coalesce, take no 2nd permit.
    Coalesced,
    /// The global wake budget or this tenant's fair-share is exhausted — DROP.
    BudgetFull,
}

// ---- egress -----------------------------------------------------------------------------------

/// A per-/24 (v4) or per-/64 (v6) destination-network key for the egress backstop.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
enum NetKey {
    V4([u8; 3]),
    V6([u8; 8]),
}

fn net_key(ip: IpAddr) -> NetKey {
    match ip {
        IpAddr::V4(a) => {
            let o = a.octets();
            NetKey::V4([o[0], o[1], o[2]])
        }
        IpAddr::V6(a) => {
            let o = a.octets();
            let mut k = [0u8; 8];
            k.copy_from_slice(&o[..8]);
            NetKey::V6(k)
        }
    }
}

struct EgressState {
    per_source: BoundedTtlMap<IpAddr, TokenBucket>,
    per_24: BoundedTtlMap<NetKey, TokenBucket>,
    per_project: BoundedTtlMap<String, TokenBucket>,
    global: TokenBucket,
    c0_global: TokenBucket,
    /// Fresh-source tracking for the one-shot C0 (a source already granted its C0 is not fresh).
    c0_sources: BoundedTtlMap<IpAddr, ()>,
}

/// Which egress aggregate cap refused a reply (design §3(c) axis 2 items 2–5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum EgressReject {
    PerSource,
    Per24,
    PerProject,
    Global,
}

// ---- last-activity + reflection kill-switch ---------------------------------------------------

/// Direction of an admitted datagram, for reflection accounting.
#[derive(Debug, Clone, Copy)]
pub(crate) enum Dir {
    In,
    Out,
}

/// One base's rolling reflection window.
struct RefWindow {
    start: Instant,
    ingress: u64,
    egress: u64,
    dests: HashSet<IpAddr>,
    dest_overflow: bool,
    amp_k: u8,
}

impl RefWindow {
    fn fresh(now: Instant, amp_k: u8) -> Self {
        Self {
            start: now,
            ingress: 0,
            egress: 0,
            dests: HashSet::new(),
            dest_overflow: false,
            amp_k,
        }
    }
}

struct ActivityState {
    /// Base → last admitted datagram (either direction); the L4-private hibernate clock (H5). NOT
    /// the shared `ActivityTracker` — the server ANDs this in without back-dating that clock.
    last: BoundedTtlMap<String, Instant>,
    /// Base → rolling reflection window.
    refl: BoundedTtlMap<String, RefWindow>,
    /// Bases currently flagged reflection-suspected (kill-switch).
    suspected: HashSet<String>,
}

struct MemCache {
    read_at: Option<Instant>,
    mib: Option<u64>,
}

/// The plane-global L4 controller. One `Arc<L4Plane>` is shared by all ports and read by the
/// server's idle + metering loops.
pub struct L4Plane {
    limits: L4PlaneLimits,
    wake: WakeCallback,
    wake_budget: Arc<Semaphore>,
    wake_state: Mutex<WakeState>,
    flow_state: Mutex<FlowState>,
    egress: Mutex<EgressState>,
    activity: Mutex<ActivityState>,
    mem: Mutex<MemCache>,
    counters: AtomicCounters,
}

impl L4Plane {
    pub fn new(limits: L4PlaneLimits, wake: WakeCallback) -> Arc<Self> {
        let now = Instant::now();
        let egress = EgressState {
            per_source: BoundedTtlMap::new(limits.source_map_max, PER_SOURCE_TTL),
            per_24: BoundedTtlMap::new(limits.source_map_max, PER_24_TTL),
            per_project: BoundedTtlMap::new(PER_PROJECT_MAP_MAX, PER_PROJECT_TTL),
            global: TokenBucket::new(
                limits.egress_global_bps as f64,
                limits.egress_global_bps as f64,
                now,
            ),
            c0_global: TokenBucket::new(
                limits.c0_grant_per_sec_global,
                // burst ≈ 0.4s of grants (mirrors the per-port burst-200 shape at 500/s default).
                (limits.c0_grant_per_sec_global * 0.4).max(1.0),
                now,
            ),
            c0_sources: BoundedTtlMap::new(limits.source_map_max, C0_SOURCE_TTL),
        };
        let wake_state = WakeState {
            wake_rate: BoundedTtlMap::new(WAKE_RATE_MAP_MAX, WAKE_RATE_TTL),
            inflight: HashMap::new(),
            tenant_inflight: HashMap::new(),
        };
        let activity = ActivityState {
            last: BoundedTtlMap::new(ACTIVITY_MAP_MAX, ACTIVITY_TTL),
            refl: BoundedTtlMap::new(REFL_MAP_MAX, REFL_TTL),
            suspected: HashSet::new(),
        };
        Arc::new(Self {
            wake_budget: Arc::new(Semaphore::new(limits.wake_budget.max(1))),
            limits,
            wake,
            wake_state: Mutex::new(wake_state),
            flow_state: Mutex::new(FlowState::default()),
            egress: Mutex::new(egress),
            activity: Mutex::new(activity),
            mem: Mutex::new(MemCache {
                read_at: None,
                mib: None,
            }),
            counters: AtomicCounters::default(),
        })
    }

    // ============================ server-facing reads (§1.2) ============================

    /// ESTABLISHED L4 flow count for a base project — the idle-loop keep-warm gate (mirrors
    /// `db_relay::conn_count`; provisional flows DO NOT count).
    pub fn conn_count(&self, base_project: &str) -> usize {
        self.flow_state
            .lock()
            .unwrap()
            .by_base
            .get(base_project)
            .map(|b| b.established)
            .unwrap_or(0)
    }

    /// Age of the last admitted L4 datagram (either direction) for a base project, or `None` if no
    /// L4 activity. The server ANDs `age > idle_timeout` into `should_hibernate` WITHOUT
    /// back-dating the shared `ActivityTracker` (mechanics H5).
    pub fn last_activity_age(&self, base_project: &str) -> Option<Duration> {
        let now = Instant::now();
        self.activity
            .lock()
            .unwrap()
            .last
            .get(&base_project.to_string())
            .map(|t| now.saturating_duration_since(*t))
    }

    /// Snapshot + reset the drop/event counters for the metering tick.
    pub fn drain_counters(&self) -> L4Counters {
        self.counters.drain()
    }

    /// Base-projects with ≥1 ESTABLISHED flow (warm-seconds accrual), EXCLUDING any currently
    /// flagged reflection-suspected (their warm-hours are unbilled by construction, §6).
    pub fn warm_projects(&self) -> Vec<String> {
        let established: Vec<String> = {
            let fs = self.flow_state.lock().unwrap();
            fs.by_base
                .iter()
                .filter(|(_, b)| b.established > 0)
                .map(|(k, _)| k.clone())
                .collect()
        };
        let act = self.activity.lock().unwrap();
        established
            .into_iter()
            .filter(|b| !act.suspected.contains(b))
            .collect()
    }

    /// Is this base-project currently reflection-suspected (kill-switch tripped)?
    pub fn is_reflection_suspected(&self, base_project: &str) -> bool {
        self.activity
            .lock()
            .unwrap()
            .suspected
            .contains(base_project)
    }

    // ============================ pump-facing internals ============================

    pub(crate) fn wake_cb(&self) -> &WakeCallback {
        &self.wake
    }

    pub(crate) fn limits(&self) -> &L4PlaneLimits {
        &self.limits
    }

    pub(crate) fn count(&self, r: DropReason) {
        let c = &self.counters;
        let field = match r {
            DropReason::RateCap => &c.rate_cap,
            DropReason::BudgetFull => &c.budget_full,
            DropReason::WarmFullGlobal => &c.warm_full_global,
            DropReason::FlowFullProject => &c.flow_full_project,
            DropReason::FlowFullGlobal => &c.flow_full_global,
            DropReason::HeaderAuthFail => &c.header_auth_fail,
            DropReason::NonceReplay => &c.nonce_replay,
            DropReason::StaleEpoch => &c.stale_epoch,
            DropReason::EgressAmpClamp => &c.egress_amp_clamp,
            DropReason::EgressPerSource => &c.egress_per_source,
            DropReason::EgressPerProject => &c.egress_per_project,
            DropReason::EgressPer24 => &c.egress_per_24,
            DropReason::EgressGlobal => &c.egress_global,
            DropReason::C0GrantRejected => &c.c0_grant_rejected,
            DropReason::ReplayBufferOverflow => &c.replay_buffer_overflow,
            DropReason::EdgeBindEaddrinuse => &c.edge_bind_eaddrinuse,
        };
        field.fetch_add(1, Ordering::Relaxed);
    }

    pub(crate) fn event(&self, e: L4Event) {
        let c = &self.counters;
        let field = match e {
            L4Event::WakeAdmitted => &c.wakes_admitted,
            L4Event::WakeCoalesced => &c.wakes_coalesced,
            L4Event::Promotion => &c.promotions,
            L4Event::ProvisionalExpired => &c.provisional_expired,
            L4Event::C0Grant => &c.c0_grants,
        };
        field.fetch_add(1, Ordering::Relaxed);
    }

    /// Axis-1 step 1: per-base-project wake-rate token bucket. `false` ⇒ DROP(`rate_cap`).
    pub(crate) fn try_wake_rate(&self, base: &str, now: Instant) -> bool {
        let mut ws = self.wake_state.lock().unwrap();
        let burst = self.limits.wake_rate_burst as f64;
        let refill = self.limits.wake_rate_refill_per_sec;
        match ws
            .wake_rate
            .get_or_insert_with(base.to_string(), now, || {
                TokenBucket::new(refill, burst, now)
            }) {
            Some(b) => b.try_take(1.0, now),
            // Wake-rate map itself at capacity (many distinct bases) ⇒ fail-closed = DROP.
            None => false,
        }
    }

    /// Axis-1 step 2: reserve a PROVISIONAL flow-table slot for `base` (owned by `tenant`),
    /// enforcing per-base + global + per-tenant-fair-share flow caps AND — when this is the base's
    /// first flow — the global distinct-warm ceiling + host-RAM floor. Does NOT touch `conn_count`.
    /// The returned [`FlowReservation`] holds the slot until dropped (flow eviction).
    pub(crate) fn try_reserve_flow(
        self: &Arc<Self>,
        base: &str,
        tenant: Option<&str>,
        now: Instant,
    ) -> Result<FlowReservation, ReserveReject> {
        // Read the RAM floor BEFORE taking the flow lock (never nest plane mutexes).
        let mem_mib = self.mem_available_mib(now);
        let mut fs = self.flow_state.lock().unwrap();
        let new_base = !fs.by_base.contains_key(base);
        if new_base {
            if fs.by_base.len() >= self.limits.global_warm_ceiling {
                return Err(ReserveReject::WarmCeiling);
            }
            if let Some(avail) = mem_mib
                && avail < self.limits.host_ram_reserve_mib
            {
                return Err(ReserveReject::Ram);
            }
        }
        let base_total = fs.by_base.get(base).map(|b| b.total).unwrap_or(0);
        if base_total >= self.limits.flow_per_project_max {
            return Err(ReserveReject::Project);
        }
        if fs.global_total >= self.limits.flow_global_max {
            return Err(ReserveReject::Global);
        }
        if let Some(t) = tenant
            && fs.tenant_total.get(t).copied().unwrap_or(0) >= self.limits.flow_global_fair_share
        {
            return Err(ReserveReject::Global);
        }
        let bf = fs.by_base.entry(base.to_string()).or_default();
        bf.total += 1;
        fs.global_total += 1;
        if let Some(t) = tenant {
            *fs.tenant_total.entry(t.to_string()).or_insert(0) += 1;
        }
        Ok(FlowReservation {
            plane: self.clone(),
            base: base.to_string(),
            tenant: tenant.map(str::to_string),
        })
    }

    /// Axis-1 steps 3+4: single-flight + global wake budget within the tenant's fair-share.
    pub(crate) fn ensure_boot(self: &Arc<Self>, base: &str, tenant: Option<&str>) -> BootAdmit {
        let mut ws = self.wake_state.lock().unwrap();
        if ws.inflight.contains_key(base) {
            return BootAdmit::Coalesced;
        }
        if let Some(t) = tenant
            && ws.tenant_inflight.get(t).copied().unwrap_or(0) >= self.limits.wake_fair_share
        {
            return BootAdmit::BudgetFull;
        }
        let permit = match self.wake_budget.clone().try_acquire_owned() {
            Ok(p) => p,
            Err(_) => return BootAdmit::BudgetFull,
        };
        ws.inflight.insert(base.to_string(), tenant.map(str::to_string));
        if let Some(t) = tenant {
            *ws.tenant_inflight.entry(t.to_string()).or_insert(0) += 1;
        }
        BootAdmit::Spawn(WakeInFlight {
            plane: self.clone(),
            base: base.to_string(),
            tenant: tenant.map(str::to_string),
            _permit: permit,
        })
    }

    /// Promotion (design §3(c)/§3(d)): the ONLY place `conn_count` moves. Enforces the per-tenant
    /// warm fair-share (a fair slice of the global warm ceiling) and returns a RAII guard that
    /// bumps `conn_count(base)` + the warm-project set; its drop decrements. `None` ⇒ leave the
    /// flow provisional (retried on its next datagram).
    pub(crate) fn try_establish(
        self: &Arc<Self>,
        base: &str,
        tenant: Option<&str>,
    ) -> Option<L4FlowGuard> {
        let mut fs = self.flow_state.lock().unwrap();
        // A reservation must already exist (the caller is promoting a live provisional flow).
        let makes_warm = match fs.by_base.get(base) {
            Some(b) => b.established == 0,
            None => return None,
        };
        if makes_warm && let Some(t) = tenant {
            let held = fs.tenant_established.get(t).map(|s| s.len()).unwrap_or(0);
            if held >= self.per_tenant_warm_share() {
                return None;
            }
        }
        if let Some(b) = fs.by_base.get_mut(base) {
            b.established += 1;
        }
        if let Some(t) = tenant {
            fs.tenant_established
                .entry(t.to_string())
                .or_default()
                .insert(base.to_string());
        }
        Some(L4FlowGuard {
            plane: self.clone(),
            base: base.to_string(),
            tenant: tenant.map(str::to_string),
        })
    }

    /// A tenant's fair slice of the global warm ceiling (distinct established bases). Derived from
    /// the same ratio as the wake fair-share (`wake_fair_share / wake_budget`), min 1 — no separate
    /// config field, and always ≤ the global ceiling.
    fn per_tenant_warm_share(&self) -> usize {
        let budget = self.limits.wake_budget.max(1);
        ((self.limits.global_warm_ceiling * self.limits.wake_fair_share) / budget)
            .max(1)
            .min(self.limits.global_warm_ceiling)
    }

    /// Try a fresh one-shot C0 grant for `dest_ip` (global rate + fresh-source). The per-port rate
    /// is checked by the caller first. Consumes the grant (marks the source, debits the global
    /// bucket) iff it returns `true`.
    pub(crate) fn try_c0_grant(&self, dest_ip: IpAddr, now: Instant) -> bool {
        let mut eg = self.egress.lock().unwrap();
        // Already granted this source its one-shot? Not fresh.
        if eg.c0_sources.contains(&dest_ip) {
            return false;
        }
        if !eg.c0_global.try_take(1.0, now) {
            return false;
        }
        // Fail-closed if the fresh-source map is full: no grant (the source's flow drops the
        // over-C0 datagram; the client retransmits within ratio credit).
        if eg
            .c0_sources
            .get_or_insert_with(dest_ip, now, || ())
            .is_none()
        {
            return false;
        }
        true
    }

    /// Axis-2 aggregate caps (per-source(IP) → per-/24 → per-project → global), evaluated in
    /// magnitude order. `Err(_)` names the tripped cap (fail-closed on any full map).
    pub(crate) fn try_egress_aggregate(
        &self,
        base: &str,
        dest_ip: IpAddr,
        bytes: usize,
        now: Instant,
    ) -> Result<(), EgressReject> {
        let mut eg = self.egress.lock().unwrap();
        let amount = bytes as f64;
        let (ps_bps, ps_burst) = (
            self.limits.per_source_bps as f64,
            self.limits.per_source_burst as f64,
        );
        // Per-source(IP /32) — map-full ⇒ fail-closed drop. (Bind then take: a match *guard*
        // can't hold the `&mut` bucket, so the take is the arm body.)
        let ok = match eg
            .per_source
            .get_or_insert_with(dest_ip, now, || TokenBucket::new(ps_bps, ps_burst, now))
        {
            Some(b) => b.try_take(amount, now),
            None => false,
        };
        if !ok {
            return Err(EgressReject::PerSource);
        }
        // Per-/24 backstop.
        let n24 = net_key(dest_ip);
        let p24_bps = self.limits.egress_per_24_bps as f64;
        let ok = match eg
            .per_24
            .get_or_insert_with(n24, now, || TokenBucket::new(p24_bps, p24_bps, now))
        {
            Some(b) => b.try_take(amount, now),
            None => false,
        };
        if !ok {
            return Err(EgressReject::Per24);
        }
        // Per-project.
        let pp_bps = self.limits.egress_per_project_bps as f64;
        let ok = match eg
            .per_project
            .get_or_insert_with(base.to_string(), now, || TokenBucket::new(pp_bps, pp_bps, now))
        {
            Some(b) => b.try_take(amount, now),
            None => false,
        };
        if !ok {
            return Err(EgressReject::PerProject);
        }
        // Global.
        if !eg.global.try_take(amount, now) {
            return Err(EgressReject::Global);
        }
        Ok(())
    }

    /// Stamp an admitted inbound datagram: refresh the L4-private hibernate clock + accrue the
    /// reflection window's ingress.
    pub(crate) fn note_ingress(&self, base: &str, bytes: usize, amp_k: u8, now: Instant) {
        self.note(base, Dir::In, bytes, amp_k, None, now);
    }

    /// Stamp an admitted outbound (reflected) datagram: refresh the clock + accrue egress + the
    /// destination for the entropy signal, and evaluate the kill-switch when the window closes.
    pub(crate) fn note_egress(
        &self,
        base: &str,
        bytes: usize,
        amp_k: u8,
        dest_ip: IpAddr,
        now: Instant,
    ) {
        self.note(base, Dir::Out, bytes, amp_k, Some(dest_ip), now);
    }

    fn note(&self, base: &str, dir: Dir, bytes: usize, amp_k: u8, dest: Option<IpAddr>, now: Instant) {
        let mut act = self.activity.lock().unwrap();
        let ActivityState {
            last,
            refl,
            suspected,
        } = &mut *act;
        // Refresh the hibernate clock (skip silently if the map is at capacity — a stamp miss only
        // makes the base look idle sooner; established flows keep it warm via conn_count).
        if let Some(t) = last.get_or_insert_with(base.to_string(), now, || now) {
            *t = now;
        }
        // Update the reflection window (skip if the map is full — fail-open on a monitor stamp,
        // never on an enforcement path).
        let Some(w) = refl.get_or_insert_with(base.to_string(), now, || RefWindow::fresh(now, amp_k))
        else {
            return;
        };
        w.amp_k = amp_k;
        match dir {
            Dir::In => w.ingress = w.ingress.saturating_add(bytes as u64),
            Dir::Out => {
                w.egress = w.egress.saturating_add(bytes as u64);
                if let Some(ip) = dest {
                    if w.dests.len() < DEST_SET_CAP {
                        w.dests.insert(ip);
                    } else {
                        w.dest_overflow = true;
                    }
                }
            }
        }
        // Evaluate + reset when the window closes.
        if now.saturating_duration_since(w.start) >= REFLECTION_WINDOW {
            let ratio_exceeded = w.egress
                > (w.amp_k.max(1) as u64)
                    .saturating_mul(w.ingress)
                    .saturating_add(REFLECTION_SLACK_BYTES);
            let entropy_exceeded = w.dest_overflow || w.dests.len() > REFLECTION_DEST_ENTROPY;
            let flag = w.egress >= REFLECTION_MIN_EGRESS && (ratio_exceeded || entropy_exceeded);
            if flag {
                suspected.insert(base.to_string());
            } else {
                suspected.remove(base);
            }
            *w = RefWindow::fresh(now, amp_k);
        }
    }

    /// Periodic maintenance the pump's sweep drives: evict TTL-expired aux-map entries so idle keys
    /// don't linger to the next access.
    pub(crate) fn sweep(&self, now: Instant) {
        {
            let mut ws = self.wake_state.lock().unwrap();
            ws.wake_rate.sweep(now);
        }
        {
            let mut eg = self.egress.lock().unwrap();
            eg.per_source.sweep(now);
            eg.per_24.sweep(now);
            eg.per_project.sweep(now);
            eg.c0_sources.sweep(now);
        }
        {
            let mut act = self.activity.lock().unwrap();
            let ActivityState { last, refl, .. } = &mut *act;
            last.sweep(now);
            refl.sweep(now);
        }
    }

    /// `/proc/meminfo` MemAvailable in MiB, cached for [`MEM_CACHE_TTL`]. `None` when unreadable
    /// (non-Linux / parse failure) — the caller treats `None` as "floor OK" so a read failure
    /// never bricks the plane, only logs.
    fn mem_available_mib(&self, now: Instant) -> Option<u64> {
        let mut mc = self.mem.lock().unwrap();
        if let Some(read_at) = mc.read_at
            && now.saturating_duration_since(read_at) < MEM_CACHE_TTL
        {
            return mc.mib;
        }
        let mib = read_mem_available_mib();
        if mib.is_none() && mc.read_at.is_none() {
            warn!("L4 plane: /proc/meminfo MemAvailable unreadable; host-RAM floor disabled");
        }
        mc.read_at = Some(now);
        mc.mib = mib;
        mib
    }
}

/// Parse `MemAvailable` (kB) out of `/proc/meminfo` → MiB. `None` on any failure.
fn read_mem_available_mib() -> Option<u64> {
    let text = std::fs::read_to_string("/proc/meminfo").ok()?;
    for line in text.lines() {
        if let Some(rest) = line.strip_prefix("MemAvailable:") {
            let kb: u64 = rest.split_whitespace().next()?.parse().ok()?;
            return Some(kb / 1024);
        }
    }
    None
}

/// RAII single-flight/wake-budget guard. Held by the spawned boot task for the boot's life;
/// on drop it releases the global permit and clears the base's inflight marker + the tenant's
/// in-flight-wake count (a hung boot's [`crate::l4_ingress`] force-drops it via a timeout).
pub(crate) struct WakeInFlight {
    plane: Arc<L4Plane>,
    base: String,
    tenant: Option<String>,
    _permit: OwnedSemaphorePermit,
}

impl Drop for WakeInFlight {
    fn drop(&mut self) {
        let mut ws = self.plane.wake_state.lock().unwrap();
        ws.inflight.remove(&self.base);
        if let Some(t) = &self.tenant
            && let Some(n) = ws.tenant_inflight.get_mut(t)
        {
            *n -= 1;
            if *n == 0 {
                ws.tenant_inflight.remove(t);
            }
        }
    }
}

/// RAII PROVISIONAL flow-table reservation (per-base/global/tenant flow caps + warm-set
/// membership). Held by the [`crate::l4_ingress`] `Flow`; drop decrements the caps and, when the
/// base loses its last flow, removes it from the warm set.
pub(crate) struct FlowReservation {
    plane: Arc<L4Plane>,
    base: String,
    tenant: Option<String>,
}

impl Drop for FlowReservation {
    fn drop(&mut self) {
        let mut fs = self.plane.flow_state.lock().unwrap();
        if let Some(bf) = fs.by_base.get_mut(&self.base) {
            bf.total = bf.total.saturating_sub(1);
            if bf.total == 0 {
                fs.by_base.remove(&self.base);
            }
        }
        fs.global_total = fs.global_total.saturating_sub(1);
        if let Some(t) = &self.tenant
            && let Some(n) = fs.tenant_total.get_mut(t)
        {
            *n -= 1;
            if *n == 0 {
                fs.tenant_total.remove(t);
            }
        }
    }
}

/// RAII ESTABLISHED guard (the `conn_count` + per-tenant warm-project gauges). Declared to drop
/// BEFORE the flow's [`FlowReservation`] so `established ≤ total` holds throughout teardown.
pub(crate) struct L4FlowGuard {
    plane: Arc<L4Plane>,
    base: String,
    tenant: Option<String>,
}

impl Drop for L4FlowGuard {
    fn drop(&mut self) {
        let mut fs = self.plane.flow_state.lock().unwrap();
        let went_cold = match fs.by_base.get_mut(&self.base) {
            Some(bf) if bf.established > 0 => {
                bf.established -= 1;
                bf.established == 0
            }
            _ => false,
        };
        if went_cold
            && let Some(t) = &self.tenant
            && let Some(set) = fs.tenant_established.get_mut(t)
        {
            set.remove(&self.base);
            if set.is_empty() {
                fs.tenant_established.remove(t);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::pin::Pin;

    fn noop_wake() -> WakeCallback {
        Arc::new(|_p: String| {
            Box::pin(async { Err(crate::WakeError::Unavailable("test".into())) })
                as Pin<Box<dyn std::future::Future<Output = _> + Send>>
        })
    }

    fn plane() -> Arc<L4Plane> {
        L4Plane::new(L4PlaneLimits::default(), noop_wake())
    }

    #[test]
    fn wake_rate_burst_then_refill() {
        let lim = L4PlaneLimits {
            wake_rate_burst: 3,
            wake_rate_refill_per_sec: 1.0,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let t = Instant::now();
        // Burst of 3 admitted...
        assert!(p.try_wake_rate("proj", t));
        assert!(p.try_wake_rate("proj", t));
        assert!(p.try_wake_rate("proj", t));
        // ...4th refused (rate cap).
        assert!(!p.try_wake_rate("proj", t));
        // 1s later, one token back.
        let t1 = t + Duration::from_secs(1);
        assert!(p.try_wake_rate("proj", t1));
        assert!(!p.try_wake_rate("proj", t1));
        // A different base has its own budget.
        assert!(p.try_wake_rate("other", t1));
    }

    #[test]
    fn reservation_enforces_warm_ceiling_and_frees_on_drop() {
        let lim = L4PlaneLimits {
            global_warm_ceiling: 2,
            host_ram_reserve_mib: 0, // don't let the RAM floor interfere
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let t = Instant::now();
        let r1 = p.try_reserve_flow("a", Some("t1"), t).unwrap();
        let _r2 = p.try_reserve_flow("b", Some("t2"), t).unwrap();
        // A 3rd DISTINCT warm base is refused at the ceiling.
        assert!(matches!(
            p.try_reserve_flow("c", Some("t3"), t),
            Err(ReserveReject::WarmCeiling)
        ));
        // A 2nd flow to an ALREADY-warm base is fine (not a new warm slot).
        let _r1b = p.try_reserve_flow("a", Some("t1"), t).unwrap();
        // Freeing base a's last... it still has r1b; drop both to cool it.
        drop(r1);
        drop(_r1b);
        // Now a 3rd distinct base fits.
        assert!(p.try_reserve_flow("c", Some("t3"), t).is_ok());
    }

    #[test]
    fn reservation_enforces_per_base_and_tenant_caps() {
        let lim = L4PlaneLimits {
            flow_per_project_max: 2,
            flow_global_fair_share: 3,
            host_ram_reserve_mib: 0,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let t = Instant::now();
        let _a1 = p.try_reserve_flow("a", Some("t"), t).unwrap();
        let _a2 = p.try_reserve_flow("a", Some("t"), t).unwrap();
        // 3rd flow to base a hits the per-base cap.
        assert!(matches!(
            p.try_reserve_flow("a", Some("t"), t),
            Err(ReserveReject::Project)
        ));
        // Tenant t has 2 flows; one more on base b is fine (share 3)...
        let _b1 = p.try_reserve_flow("b", Some("t"), t).unwrap();
        // ...but a 4th anywhere hits the tenant's global fair-share.
        assert!(matches!(
            p.try_reserve_flow("c", Some("t"), t),
            Err(ReserveReject::Global)
        ));
    }

    #[test]
    fn establish_moves_conn_count_only_on_promotion() {
        let p = plane();
        let t = Instant::now();
        let _r = p.try_reserve_flow("a", Some("t"), t).unwrap();
        // Reserved but not established: conn_count stays 0.
        assert_eq!(p.conn_count("a"), 0);
        assert!(p.warm_projects().is_empty());
        let g = p.try_establish("a", Some("t")).unwrap();
        assert_eq!(p.conn_count("a"), 1);
        assert_eq!(p.warm_projects(), vec!["a".to_string()]);
        drop(g);
        assert_eq!(p.conn_count("a"), 0);
        assert!(p.warm_projects().is_empty());
    }

    #[test]
    fn establish_without_reservation_is_none() {
        let p = plane();
        // No reservation ⇒ can't promote a non-existent flow.
        assert!(p.try_establish("ghost", Some("t")).is_none());
    }

    #[test]
    fn per_tenant_warm_share_is_enforced() {
        // Force the derived share to 1 (ceiling*share/budget = 4*1/4 = 1).
        let lim = L4PlaneLimits {
            global_warm_ceiling: 4,
            wake_fair_share: 1,
            wake_budget: 4,
            host_ram_reserve_mib: 0,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let t = Instant::now();
        let _r1 = p.try_reserve_flow("a", Some("t"), t).unwrap();
        let _r2 = p.try_reserve_flow("b", Some("t"), t).unwrap();
        let _g1 = p.try_establish("a", Some("t")).unwrap();
        // The tenant already holds 1 warm base; a 2nd distinct established base is refused.
        assert!(p.try_establish("b", Some("t")).is_none());
    }

    #[test]
    fn ensure_boot_single_flight_and_budget() {
        let lim = L4PlaneLimits {
            wake_budget: 2,
            wake_fair_share: 2,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        // First wake for base a spawns (takes a permit).
        let g1 = match p.ensure_boot("a", Some("t")) {
            BootAdmit::Spawn(g) => g,
            _ => panic!("expected Spawn"),
        };
        // A second packet for the SAME base coalesces (no 2nd permit).
        assert!(matches!(p.ensure_boot("a", Some("t")), BootAdmit::Coalesced));
        // A different base takes the 2nd permit.
        let _g2 = match p.ensure_boot("b", Some("t2")) {
            BootAdmit::Spawn(g) => g,
            _ => panic!("expected Spawn"),
        };
        // Budget now exhausted for a third distinct base.
        assert!(matches!(p.ensure_boot("c", Some("t3")), BootAdmit::BudgetFull));
        // Releasing a1's boot frees the permit + inflight.
        drop(g1);
        assert!(matches!(p.ensure_boot("c", Some("t3")), BootAdmit::Spawn(_)));
    }

    #[test]
    fn ensure_boot_tenant_fair_share() {
        let lim = L4PlaneLimits {
            wake_budget: 8,
            wake_fair_share: 1,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let _g = match p.ensure_boot("a", Some("t")) {
            BootAdmit::Spawn(g) => g,
            _ => panic!(),
        };
        // Same tenant, different base: over the tenant's fair-share of 1 (even though budget=8).
        assert!(matches!(p.ensure_boot("b", Some("t")), BootAdmit::BudgetFull));
        // A different tenant still gets its share.
        assert!(matches!(p.ensure_boot("c", Some("u")), BootAdmit::Spawn(_)));
    }

    #[test]
    fn egress_aggregate_trips_the_right_cap() {
        let t = Instant::now();
        // --- per-source(IP): a tight per-source burst trips first (it's checked first). ---
        let lim = L4PlaneLimits {
            per_source_bps: 1000,
            per_source_burst: 1000,
            egress_per_24_bps: 1_000_000,
            egress_per_project_bps: 1_000_000,
            egress_global_bps: 1_000_000,
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let ip: IpAddr = "203.0.113.9".parse().unwrap();
        assert!(p.try_egress_aggregate("a", ip, 1000, t).is_ok());
        assert_eq!(
            p.try_egress_aggregate("a", ip, 1, t).unwrap_err(),
            EgressReject::PerSource
        );

        // --- per-project: per-source generous, distinct /24s, tight project cap. ---
        let lim2 = L4PlaneLimits {
            per_source_bps: 1_000_000,
            per_source_burst: 1_000_000,
            egress_per_24_bps: 1_000_000,
            egress_per_project_bps: 10_000,
            egress_global_bps: 1_000_000,
            ..Default::default()
        };
        let p2 = L4Plane::new(lim2, noop_wake());
        let ip_a: IpAddr = "203.0.113.9".parse().unwrap();
        let ip_b: IpAddr = "198.51.100.9".parse().unwrap(); // different /24
        assert!(p2.try_egress_aggregate("proj", ip_a, 6000, t).is_ok());
        // The 2nd 6000 pushes the project past 10_000 (per-source + per-/24 both fit).
        assert_eq!(
            p2.try_egress_aggregate("proj", ip_b, 6000, t).unwrap_err(),
            EgressReject::PerProject
        );
    }

    #[test]
    fn c0_grant_is_fresh_source_and_rate_limited() {
        let lim = L4PlaneLimits {
            c0_grant_per_sec_global: 1.0, // tiny global burst
            ..Default::default()
        };
        let p = L4Plane::new(lim, noop_wake());
        let t = Instant::now();
        let a: IpAddr = "198.51.100.1".parse().unwrap();
        let b: IpAddr = "198.51.100.2".parse().unwrap();
        // First fresh source gets a grant...
        assert!(p.try_c0_grant(a, t));
        // ...the SAME source is no longer fresh.
        assert!(!p.try_c0_grant(a, t));
        // A different fresh source is refused by the exhausted global rate (burst ~0.4).
        assert!(!p.try_c0_grant(b, t));
    }

    #[test]
    fn reflection_kill_switch_trips_on_high_ratio() {
        let p = plane();
        let t0 = Instant::now();
        let victim: IpAddr = "192.0.2.50".parse().unwrap();
        // Tiny ingress, large sustained egress at k=1 → after the window closes, suspected.
        p.note_ingress("bad", 1000, 1, t0);
        p.note_egress("bad", 1_000_000, 1, victim, t0);
        assert!(!p.is_reflection_suspected("bad")); // window not closed yet
        // A datagram past the window boundary triggers evaluation.
        let t1 = t0 + REFLECTION_WINDOW + Duration::from_millis(1);
        p.note_egress("bad", 1, 1, victim, t1);
        assert!(p.is_reflection_suspected("bad"));
        assert!(p.warm_projects().is_empty()); // suspected excluded from warm accrual
    }

    #[test]
    fn reflection_clears_on_a_clean_window() {
        let p = plane();
        let t0 = Instant::now();
        let victim: IpAddr = "192.0.2.51".parse().unwrap();
        p.note_ingress("x", 1000, 1, t0);
        p.note_egress("x", 1_000_000, 1, victim, t0);
        let t1 = t0 + REFLECTION_WINDOW + Duration::from_millis(1);
        p.note_egress("x", 1, 1, victim, t1);
        assert!(p.is_reflection_suspected("x"));
        // A clean window (egress <= ingress) clears the flag.
        p.note_ingress("x", 1_000_000, 1, t1);
        let t2 = t1 + REFLECTION_WINDOW + Duration::from_millis(1);
        p.note_ingress("x", 1, 1, t2);
        assert!(!p.is_reflection_suspected("x"));
    }

    #[test]
    fn last_activity_age_tracks_stamps() {
        let p = plane();
        assert!(p.last_activity_age("z").is_none());
        let t = Instant::now();
        p.note_ingress("z", 10, 1, t);
        // Age is small and defined now.
        assert!(p.last_activity_age("z").is_some());
    }

    #[test]
    fn counters_drain_and_reset() {
        let p = plane();
        p.count(DropReason::RateCap);
        p.count(DropReason::RateCap);
        p.count(DropReason::EgressAmpClamp);
        p.event(L4Event::Promotion);
        let c = p.drain_counters();
        assert_eq!(c.rate_cap, 2);
        assert_eq!(c.egress_amp_clamp, 1);
        assert_eq!(c.promotions, 1);
        // Drained → reset.
        let c2 = p.drain_counters();
        assert_eq!(c2.rate_cap, 0);
    }
}
