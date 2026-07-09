//! Pure, I/O-free primitives for the L4 UDP **anti-reflection** controls (design §3(c) axis 2,
//! P0-L4-6). Everything here is `&mut self` arithmetic over `Instant` — no tokio, no sockets —
//! exactly like [`jkbase_common::db_preamble`], so the load-bearing bounds are exhaustively
//! unit-testable in isolation. The plane ([`crate::l4_plane`]) wraps these behind mutexes; the
//! pump ([`crate::l4_ingress`]) drives them per datagram.
//!
//! Three primitives, each a distinct security bound:
//! - [`TokenBucket`] — a generic byte/count rate cap (the per-source(IP), per-/24, per-project,
//!   global egress ceilings and the C0-grant / wake-rate limiters are all instances).
//! - [`RatioCredit`] — the per-flow amplification clamp: egress is permitted only up to
//!   `amp_k × ingress` bytes (default `k=1`, byte-for-byte), with a **one-shot** `C0` floor for
//!   the single first-reply-bigger-than-request datagram. This is THE core reflection bound.
//! - [`BoundedTtlMap`] — a cardinality-bounded, TTL-evicting map, **fail-closed on overflow**
//!   (a full map denies a new key rather than evicting a live limiter — the accepted `C0`-spray
//!   residual would otherwise grow the per-source map without bound; P0-L4-5/-9).

use std::collections::HashMap;
use std::hash::Hash;
use std::time::{Duration, Instant};

/// A leaky/token bucket over an abstract unit (bytes for the egress caps, whole tokens for the
/// wake-rate + C0-grant limiters). Starts **full** (a fresh limiter admits a burst immediately),
/// refills continuously at `rate` per second up to `capacity`, and never queues — an over-budget
/// take is refused (the caller DROPs; P0-L4-6 "drop, not queue").
#[derive(Debug, Clone)]
pub struct TokenBucket {
    /// Refill rate, units per second.
    rate: f64,
    /// Burst ceiling (max accumulated units).
    capacity: f64,
    /// Currently available units.
    tokens: f64,
    /// Last refill timestamp.
    last: Instant,
}

impl TokenBucket {
    /// A bucket refilling at `rate`/s with burst `capacity`, starting full as of `now`. `rate`
    /// and `capacity` are clamped non-negative; a zero-capacity bucket admits nothing (fail-closed
    /// for an absurd config, never a panic).
    pub fn new(rate: f64, capacity: f64, now: Instant) -> Self {
        let capacity = capacity.max(0.0);
        Self {
            rate: rate.max(0.0),
            capacity,
            tokens: capacity,
            last: now,
        }
    }

    /// Accrue tokens for the elapsed wall time (monotonic `Instant`, so a backwards step is
    /// impossible; `saturating_duration_since` is belt-and-suspenders).
    fn refill(&mut self, now: Instant) {
        let dt = now.saturating_duration_since(self.last).as_secs_f64();
        if dt > 0.0 {
            self.tokens = (self.tokens + dt * self.rate).min(self.capacity);
            self.last = now;
        }
    }

    /// Try to spend `amount` units at `now`. Returns `true` (and debits) iff enough are available;
    /// otherwise leaves the bucket untouched and returns `false` (the caller drops the datagram).
    pub fn try_take(&mut self, amount: f64, now: Instant) -> bool {
        self.refill(now);
        if self.tokens >= amount {
            self.tokens -= amount;
            true
        } else {
            false
        }
    }
}

/// Verdict of a [`RatioCredit::try_egress`] check.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RatioVerdict {
    /// Enough ratio credit — already debited; send it.
    Allowed,
    /// Not enough credit, but the flow's one-shot `C0` floor could cover it AND the datagram
    /// fits within `credit + C0`. The caller must obtain a rate-limited `C0` grant (per-port +
    /// global + fresh-source) and, iff granted, call [`RatioCredit::commit_c0`] before sending.
    /// If the grant is refused the datagram is dropped (nothing is debited here).
    NeedC0,
    /// Refused: the flow's one-shot is already spent, or the datagram exceeds even `credit + C0`.
    /// Drop it (`egress_amp_clamp`) — never queue (UDP datagrams are indivisible; P0-L4-6).
    Denied,
}

/// The per-flow **amplification clamp** (design §3(c) axis 2, item 1). Ingress bytes accrue
/// `amp_k ×` credit; egress bytes spend it 1:1; egress is permitted only while credit stays ≥ 0,
/// so *sustained* reflected volume is bounded to `amp_k ×` the attacker's own inbound (default
/// `k=1`). A brand-new flow gets exactly **one** `C0` grant letting credit dip to `−C0` once, so a
/// legitimate first reply larger than the handshake request (DTLS/QUIC cert chain, game
/// connect→snapshot) is not silently dropped whole (mechanics H6). Credit is capped
/// ([`CREDIT_CAP`]) so a client cannot bank unbounded credit during a long silent-egress phase
/// and later burst-reflect it.
#[derive(Debug, Clone, Default)]
pub struct RatioCredit {
    /// Signed available egress credit, bytes. Only ever `< 0` transiently via the one-shot `C0`.
    credit: i64,
    /// Whether this flow's single `C0` dip has been spent.
    c0_used: bool,
}

/// Ceiling on banked ratio credit (bytes). Bounds a "send slowly, reflect in one burst" move; the
/// absolute per-source/per-project/global buckets are the other half of that defense.
pub const CREDIT_CAP: i64 = 256 * 1024;

impl RatioCredit {
    pub fn new() -> Self {
        Self::default()
    }

    /// Account `bytes` of admitted **inbound** traffic: accrue `amp_k × bytes` of egress credit,
    /// clamped to [`CREDIT_CAP`]. `amp_k` is the port's resolved `1..=3` ratio.
    pub fn on_ingress(&mut self, bytes: usize, amp_k: u8) {
        let add = (amp_k.max(1) as i64).saturating_mul(bytes as i64);
        self.credit = self.credit.saturating_add(add).min(CREDIT_CAP);
    }

    /// Can this flow afford to reflect `bytes` right now? Debits on [`RatioVerdict::Allowed`];
    /// leaves state untouched on `NeedC0`/`Denied`. `c0_bytes` is the one-shot floor size.
    pub fn try_egress(&mut self, bytes: usize, c0_bytes: u64) -> RatioVerdict {
        let b = bytes as i64;
        if self.credit >= b {
            self.credit -= b;
            return RatioVerdict::Allowed;
        }
        // Insufficient ratio credit. The one-shot C0 can cover a *single* datagram whose deficit
        // fits within C0, and only if this flow hasn't used its dip yet.
        if self.c0_used {
            return RatioVerdict::Denied;
        }
        let deficit = b - self.credit; // > 0
        if deficit > c0_bytes as i64 {
            return RatioVerdict::Denied;
        }
        RatioVerdict::NeedC0
    }

    /// Commit a granted one-shot `C0` send of `bytes`: debit (credit goes to `≥ −C0`) and burn the
    /// dip. Call ONLY after [`RatioVerdict::NeedC0`] and a successful external grant.
    pub fn commit_c0(&mut self, bytes: usize) {
        self.credit -= bytes as i64;
        self.c0_used = true;
    }
}

/// A `HashMap` with a hard cardinality bound and TTL eviction that is **fail-closed on overflow**:
/// when full and asked for an absent key it evicts only *expired* entries to make room, and if
/// none are expired it refuses (`None`) rather than evict a live entry. Evicting a live limiter to
/// admit a churned key would reset that victim's rate cap — an attacker rotating keys (source IPs)
/// could mint fresh budget forever — so the correct posture is to deny the newcomer's egress
/// (P0-L4-5/-9). Used for every per-key aux map (per-source, per-/24, per-project, C0-source,
/// wake-rate, last-activity, reflection windows).
pub struct BoundedTtlMap<K, V> {
    map: HashMap<K, (V, Instant)>,
    max: usize,
    ttl: Duration,
}

impl<K: Eq + Hash + Clone, V> BoundedTtlMap<K, V> {
    pub fn new(max: usize, ttl: Duration) -> Self {
        Self {
            map: HashMap::new(),
            max: max.max(1),
            ttl,
        }
    }

    /// Drop entries untouched for longer than the TTL.
    fn evict_expired(&mut self, now: Instant) {
        let ttl = self.ttl;
        self.map
            .retain(|_, (_, t)| now.saturating_duration_since(*t) < ttl);
    }

    /// Get the entry for `key` (touching its TTL), creating it via `make` if absent. Returns
    /// `None` **only** when the map is at capacity, the key is absent, and no entry is expired —
    /// the fail-closed overflow path (the caller drops).
    pub fn get_or_insert_with(
        &mut self,
        key: K,
        now: Instant,
        make: impl FnOnce() -> V,
    ) -> Option<&mut V> {
        // Only a genuinely-new key can push us over capacity; reclaim expired entries first, then
        // refuse if still full (never evict a live entry to seat a newcomer).
        if !self.map.contains_key(&key) && self.map.len() >= self.max {
            self.evict_expired(now);
            if self.map.len() >= self.max {
                return None;
            }
        }
        let slot = self.map.entry(key).or_insert_with(|| (make(), now));
        slot.1 = now;
        Some(&mut slot.0)
    }

    /// Read an entry WITHOUT touching its TTL or inserting (for gauges / age reads). A
    /// TTL-expired-but-not-yet-swept entry may still be returned — callers that care sweep first.
    pub fn get(&self, key: &K) -> Option<&V> {
        self.map.get(key).map(|(v, _)| v)
    }

    /// Whether `key` currently has a (possibly stale) entry.
    pub fn contains(&self, key: &K) -> bool {
        self.map.contains_key(key)
    }

    /// Sweep expired entries (call from a periodic tick to keep the map from holding idle keys to
    /// the next `get_or_insert_with`).
    pub fn sweep(&mut self, now: Instant) {
        self.evict_expired(now);
    }

    /// Live entry count (a bounded gauge — the per-source / per-/24 map cardinality §5 exports).
    pub fn len(&self) -> usize {
        self.map.len()
    }

    pub fn is_empty(&self) -> bool {
        self.map.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn t0() -> Instant {
        Instant::now()
    }

    #[test]
    fn token_bucket_starts_full_refills_and_never_queues() {
        let t = t0();
        // 100 units/s, burst 10 — starts full.
        let mut b = TokenBucket::new(100.0, 10.0, t);
        // Spend the whole burst.
        assert!(b.try_take(10.0, t));
        // Empty now: an immediate take is refused (dropped, not queued).
        assert!(!b.try_take(1.0, t));
        // After 50ms at 100/s → +5 tokens.
        let t1 = t + Duration::from_millis(50);
        assert!(b.try_take(5.0, t1));
        assert!(!b.try_take(0.01, t1));
        // Refill is capped at the burst ceiling (a long idle can't over-fill).
        let t2 = t1 + Duration::from_secs(100);
        assert!(b.try_take(10.0, t2));
        assert!(!b.try_take(0.01, t2));
    }

    #[test]
    fn token_bucket_absurd_config_admits_nothing() {
        let t = t0();
        let mut b = TokenBucket::new(-5.0, 0.0, t);
        assert!(!b.try_take(1.0, t));
        // A zero-amount take is trivially allowed (no bytes to send).
        assert!(b.try_take(0.0, t));
    }

    #[test]
    fn ratio_credit_holds_sustained_k_times_ingress() {
        // k = 1: egress may never exceed cumulative ingress.
        let mut c = RatioCredit::new();
        c.on_ingress(1000, 1);
        assert_eq!(c.try_egress(600, 1500), RatioVerdict::Allowed); // 600 <= 1000
        assert_eq!(c.try_egress(400, 1500), RatioVerdict::Allowed); // exact remainder
        // Now credit == 0; any further egress needs the (still-available) C0 one-shot.
        assert_eq!(c.try_egress(1, 1500), RatioVerdict::NeedC0);
    }

    #[test]
    fn ratio_credit_amp_k_scales_allowance() {
        // k = 3: 100 ingress bytes buys 300 egress credit.
        let mut c = RatioCredit::new();
        c.on_ingress(100, 3);
        assert_eq!(c.try_egress(300, 1500), RatioVerdict::Allowed);
        assert_eq!(c.try_egress(1, 1500), RatioVerdict::NeedC0);
    }

    #[test]
    fn ratio_credit_c0_is_one_shot_only() {
        let mut c = RatioCredit::new();
        // No ingress yet: a first reply of 1200 (< C0 1500) needs a C0 grant.
        assert_eq!(c.try_egress(1200, 1500), RatioVerdict::NeedC0);
        c.commit_c0(1200); // grant obtained + committed → credit = -1200
        // The one-shot is now spent: a second deficit datagram is DENIED, not another NeedC0.
        assert_eq!(c.try_egress(50, 1500), RatioVerdict::Denied);
        // Feeding ingress restores normal ratio credit (must first climb out of the -1200 hole).
        c.on_ingress(1300, 1); // credit = 100
        assert_eq!(c.try_egress(100, 1500), RatioVerdict::Allowed);
        assert_eq!(c.try_egress(1, 1500), RatioVerdict::Denied); // c0 already used
    }

    #[test]
    fn ratio_credit_rejects_datagram_bigger_than_credit_plus_c0() {
        let mut c = RatioCredit::new();
        c.on_ingress(100, 1); // credit = 100
        // Deficit 5000-100 = 4900 > C0 1500 → cannot be covered even by the one-shot.
        assert_eq!(c.try_egress(5000, 1500), RatioVerdict::Denied);
    }

    #[test]
    fn ratio_credit_is_capped() {
        let mut c = RatioCredit::new();
        // Bank far more than the cap...
        c.on_ingress(usize::try_from(CREDIT_CAP).unwrap() * 4, 1);
        // ...only CREDIT_CAP is retained: a burst beyond it is refused.
        assert_eq!(
            c.try_egress(usize::try_from(CREDIT_CAP).unwrap(), 1500),
            RatioVerdict::Allowed
        );
        assert_eq!(c.try_egress(1, 1500), RatioVerdict::NeedC0);
    }

    #[test]
    fn bounded_map_is_fail_closed_on_overflow() {
        let t = t0();
        let mut m: BoundedTtlMap<u32, TokenBucket> = BoundedTtlMap::new(2, Duration::from_secs(60));
        assert!(m.get_or_insert_with(1, t, || TokenBucket::new(1.0, 1.0, t)).is_some());
        assert!(m.get_or_insert_with(2, t, || TokenBucket::new(1.0, 1.0, t)).is_some());
        // Full + all entries live ⇒ a third distinct key is REFUSED (fail-closed), not seated by
        // evicting a live limiter.
        assert!(m.get_or_insert_with(3, t, || TokenBucket::new(1.0, 1.0, t)).is_none());
        // An existing key is still served (no growth).
        assert!(m.get_or_insert_with(1, t, || unreachable!()).is_some());
        assert_eq!(m.len(), 2);
    }

    #[test]
    fn bounded_map_ttl_reclaims_then_admits() {
        let t = t0();
        let mut m: BoundedTtlMap<u32, u64> = BoundedTtlMap::new(1, Duration::from_secs(10));
        assert!(m.get_or_insert_with(1, t, || 10).is_some());
        // Key 2 while key 1 is still fresh ⇒ refused.
        assert!(m.get_or_insert_with(2, t, || 20).is_none());
        // 11s later key 1 is expired ⇒ reclaimed to seat key 2.
        let t1 = t + Duration::from_secs(11);
        assert!(m.get_or_insert_with(2, t1, || 20).is_some());
        assert_eq!(m.len(), 1);
        assert!(m.contains(&2) && !m.contains(&1));
    }
}
