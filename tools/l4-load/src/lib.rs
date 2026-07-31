//! Shared wire + statistics primitives for the L4 UDP load harness.
//!
//! The harness answers one question the L4 plane has never been asked: **does the datagram pump
//! hold at SFU media rates?** Every shipped test drives it at voice/game rates (tens of pps, one
//! flow). A conference SFU is a different animal — the *egress* leg carries `(N-1)` fan-out
//! streams per participant, so the plane's per-datagram HMAC seal/open, flow-table lookup and
//! four-level egress token-bucket arithmetic run tens of thousands of times a second, and the
//! bounds in `l4_plane::L4PlaneLimits` bite on the reply path, not the request path.
//!
//! Two deliberate modelling choices, both load-bearing:
//!
//! 1. **Asymmetric by construction.** A naive echo probe (1 reply per request) can never trip
//!    `egress_per_source` / `egress_per_project` / `RatioCredit`, because those gates only fire
//!    when egress outruns ingress — exactly the shape an SFU has and an echo does not. The guest
//!    simulator therefore emits an *unsolicited* downstream at a configured rate per admitted
//!    flow, driven by a tiny JOIN control datagram. That is the SFU shape, and it is the only
//!    shape that exercises the reflection controls the way real media will.
//! 2. **One flow per participant, one port.** Matches mediasoup `WebRtcServer` (a single UDP
//!    socket per worker, transports demuxed by ICE ufrag), which is the only mediasoup topology
//!    that fits a per-port L4 plane. Flow count therefore tracks participant count, not transport
//!    count — the `flow_per_project_max: 256` bound is nowhere near it.
//!
//! Zero dependencies on purpose: the simulator half is deployed *as a jkbase project*, so it
//! builds inside a network-fenced build VM. No crates.io fetch, no buildpack surprises, seconds
//! to compile.

use std::net::UdpSocket;
use std::time::{Duration, Instant};

// ---------------------------------------------------------------------------
// Wire format
// ---------------------------------------------------------------------------

/// `"L4"` — rejects stray traffic on a shared port without pretending to be authentication. The
/// transit seam's real authenticity gate is the agent's HMAC header (`jkbase_common::l4_transit`);
/// this is a sanity byte, nothing more.
pub const MAGIC: u16 = 0x4C34;

/// `magic(2) ‖ kind(1) ‖ class(1) ‖ seq(4) ‖ stamp(8)`, big-endian. Payload padding follows to
/// reach the requested datagram size, so a packet is exactly as big as the profile asks for.
pub const HDR_LEN: usize = 16;

/// Largest datagram the harness will build or accept. Above the Ethernet MTU the transit leg
/// fragments and the measurement stops meaning what it says, so the harness refuses rather than
/// silently reporting fragmented nonsense.
pub const MAX_DATAGRAM: usize = 1500;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    /// Client → sim: admit this flow and start its downstream at the carried profile.
    Join = 1,
    /// Client → sim: one uplink media packet (counted, never echoed — an SFU does not echo).
    Up = 2,
    /// Sim → client: one downstream fan-out packet.
    Down = 3,
    /// Client → sim: RTT probe. Echoed verbatim as [`Kind::Pong`] with the client's own stamp,
    /// so RTT needs no clock synchronisation between the two boxes.
    Ping = 4,
    /// Sim → client: the echo of a [`Kind::Ping`].
    Pong = 5,
    /// Client → sim: stop this flow's downstream now (clean teardown, so a run's tail doesn't
    /// leak emitters into the next run).
    Leave = 6,
}

impl Kind {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            1 => Kind::Join,
            2 => Kind::Up,
            3 => Kind::Down,
            4 => Kind::Ping,
            5 => Kind::Pong,
            6 => Kind::Leave,
            _ => return None,
        })
    }
}

/// Traffic class. Video and audio are tracked as independent sequence spaces because they have
/// wildly different packet sizes and pps, and a cap that shapes bytes hurts them differently —
/// collapsing them into one series would hide which one is being starved.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Class {
    Ctl = 0,
    Video = 1,
    Audio = 2,
}

impl Class {
    pub fn from_u8(b: u8) -> Option<Self> {
        Some(match b {
            0 => Class::Ctl,
            1 => Class::Video,
            2 => Class::Audio,
            _ => return None,
        })
    }
}

/// A parsed harness datagram header.
#[derive(Debug, Clone, Copy)]
pub struct Header {
    pub kind: Kind,
    pub class: Class,
    pub seq: u32,
    /// Sender's monotonic nanos. Only ever compared against another reading of the **same**
    /// clock (RTT echoes the client's own stamp; jitter differences cancel a constant offset),
    /// so the two ends are never assumed to share a time base.
    pub stamp: u64,
}

/// Write a header into `buf[..HDR_LEN]`. Caller owns the padding beyond it.
pub fn put_header(buf: &mut [u8], h: Header) {
    buf[0..2].copy_from_slice(&MAGIC.to_be_bytes());
    buf[2] = h.kind as u8;
    buf[3] = h.class as u8;
    buf[4..8].copy_from_slice(&h.seq.to_be_bytes());
    buf[8..16].copy_from_slice(&h.stamp.to_be_bytes());
}

/// Parse a header, or `None` if the datagram is short or not ours (fail-closed: an unparseable
/// datagram is dropped and counted, never guessed at).
pub fn parse_header(buf: &[u8]) -> Option<Header> {
    if buf.len() < HDR_LEN {
        return None;
    }
    if u16::from_be_bytes([buf[0], buf[1]]) != MAGIC {
        return None;
    }
    Some(Header {
        kind: Kind::from_u8(buf[2])?,
        class: Class::from_u8(buf[3])?,
        seq: u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]),
        stamp: u64::from_be_bytes([
            buf[8], buf[9], buf[10], buf[11], buf[12], buf[13], buf[14], buf[15],
        ]),
    })
}

/// The downstream profile a client requests in its JOIN body: what the simulated SFU should fan
/// back at it. `v_*` is the video series, `a_*` the audio series.
///
/// Encoded as `v_pps(4) ‖ v_bytes(2) ‖ a_pps(4) ‖ a_bytes(2)` after the header.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinProfile {
    pub v_pps: u32,
    pub v_bytes: u16,
    pub a_pps: u32,
    pub a_bytes: u16,
}

pub const JOIN_BODY_LEN: usize = 12;

impl JoinProfile {
    pub fn encode(&self, out: &mut [u8]) {
        out[0..4].copy_from_slice(&self.v_pps.to_be_bytes());
        out[4..6].copy_from_slice(&self.v_bytes.to_be_bytes());
        out[6..10].copy_from_slice(&self.a_pps.to_be_bytes());
        out[10..12].copy_from_slice(&self.a_bytes.to_be_bytes());
    }

    /// Decode + **clamp**. A JOIN arrives from an untrusted client, and the simulator turns it
    /// straight into a send rate; an unclamped `v_pps` would let one datagram conscript the sim
    /// into a flood. Clamped to something a conference could plausibly ask for.
    pub fn decode(body: &[u8]) -> Option<Self> {
        if body.len() < JOIN_BODY_LEN {
            return None;
        }
        let v_pps = u32::from_be_bytes([body[0], body[1], body[2], body[3]]).min(200_000);
        let v_bytes = u16::from_be_bytes([body[4], body[5]])
            .max(HDR_LEN as u16)
            .min(MAX_DATAGRAM as u16);
        let a_pps = u32::from_be_bytes([body[6], body[7], body[8], body[9]]).min(200_000);
        let a_bytes = u16::from_be_bytes([body[10], body[11]])
            .max(HDR_LEN as u16)
            .min(MAX_DATAGRAM as u16);
        Some(JoinProfile {
            v_pps,
            v_bytes,
            a_pps,
            a_bytes,
        })
    }

    /// Offered downstream bytes/sec for this profile — the number to compare against
    /// `L4PlaneLimits::per_source_bps` (1 MiB/s by default), since the per-source egress bucket
    /// is keyed on the *destination* IP, i.e. one bucket per participant.
    pub fn offered_bps(&self) -> u64 {
        self.v_pps as u64 * self.v_bytes as u64 + self.a_pps as u64 * self.a_bytes as u64
    }
}

// ---------------------------------------------------------------------------
// Pacing
// ---------------------------------------------------------------------------

/// A deadline-accumulating pacer. Deadlines advance from a fixed origin rather than from "now +
/// interval", so a slow send never lets the series drift permanently behind — the harness must
/// not silently under-offer load and then report the shortfall as the plane's fault.
///
/// Above `SPIN_THRESHOLD` pps, `thread::sleep` granularity (~50–100µs, worse under load) becomes
/// a larger error than the interval itself, so the pacer switches to a yielding spin. Burning a
/// core to keep the offered rate honest is the right trade for a load generator.
pub struct Pacer {
    origin: Instant,
    interval_nanos: u128,
    sent: u128,
}

/// Above this rate, sleep-based pacing costs more accuracy than it saves CPU.
const SPIN_THRESHOLD: u32 = 2_000;

impl Pacer {
    pub fn new(pps: u32, origin: Instant) -> Self {
        let interval_nanos = if pps == 0 {
            0
        } else {
            1_000_000_000u128 / pps as u128
        };
        Self {
            origin,
            interval_nanos,
            sent: 0,
        }
    }

    pub fn idle(&self) -> bool {
        self.interval_nanos == 0
    }

    /// Block until the next packet is due, then account for it. Returns `false` if this pacer
    /// is idle (zero pps) — the caller should park instead of hot-looping.
    pub fn wait(&mut self, pps: u32) -> bool {
        if self.idle() {
            return false;
        }
        let due = Duration::from_nanos((self.sent * self.interval_nanos) as u64);
        loop {
            let elapsed = self.origin.elapsed();
            if elapsed >= due {
                break;
            }
            let remaining = due - elapsed;
            if pps <= SPIN_THRESHOLD && remaining > Duration::from_micros(200) {
                std::thread::sleep(remaining - Duration::from_micros(100));
            } else {
                std::hint::spin_loop();
                std::thread::yield_now();
            }
        }
        self.sent += 1;
        true
    }
}

// ---------------------------------------------------------------------------
// Receive-side statistics
// ---------------------------------------------------------------------------

/// Per-class receive accounting for one direction of one flow.
///
/// Loss is derived from the sequence span rather than a running gap count, so reordering is not
/// double-counted as loss: `lost = (highest - first + 1) - received`. Reorder is reported
/// separately because a relay that reorders is a materially different (and, for RTP, more
/// tolerable) failure than one that drops.
#[derive(Debug, Default, Clone)]
pub struct SeriesStats {
    pub packets: u64,
    pub bytes: u64,
    pub first_seq: Option<u32>,
    pub highest_seq: u32,
    pub reordered: u64,
    /// RFC 3550 interarrival jitter estimate, in nanoseconds.
    pub jitter_nanos: f64,
    last_transit: Option<i128>,
}

impl SeriesStats {
    /// Record one received packet. `stamp` is the sender's clock, `arrival` ours; only their
    /// *difference over time* is used, so a constant offset between the two clocks cancels.
    pub fn record(&mut self, seq: u32, len: usize, stamp: u64, arrival_nanos: u64) {
        self.packets += 1;
        self.bytes += len as u64;
        if self.first_seq.is_none() {
            self.first_seq = Some(seq);
            self.highest_seq = seq;
        } else if seq > self.highest_seq {
            self.highest_seq = seq;
        } else {
            self.reordered += 1;
        }

        let transit = arrival_nanos as i128 - stamp as i128;
        if let Some(prev) = self.last_transit {
            let d = (transit - prev).unsigned_abs() as f64;
            self.jitter_nanos += (d - self.jitter_nanos) / 16.0;
        }
        self.last_transit = Some(transit);
    }

    /// Packets the sender must have emitted across the observed sequence span.
    pub fn expected(&self) -> u64 {
        match self.first_seq {
            Some(first) if self.highest_seq >= first => (self.highest_seq - first) as u64 + 1,
            Some(_) => self.packets,
            None => 0,
        }
    }

    pub fn lost(&self) -> u64 {
        self.expected().saturating_sub(self.packets)
    }

    pub fn loss_pct(&self) -> f64 {
        let e = self.expected();
        if e == 0 {
            0.0
        } else {
            self.lost() as f64 * 100.0 / e as f64
        }
    }

    pub fn bps(&self, dur: Duration) -> f64 {
        let s = dur.as_secs_f64();
        if s <= 0.0 {
            0.0
        } else {
            self.bytes as f64 / s
        }
    }

    pub fn pps(&self, dur: Duration) -> f64 {
        let s = dur.as_secs_f64();
        if s <= 0.0 {
            0.0
        } else {
            self.packets as f64 / s
        }
    }
}

/// Sorted-sample percentile in nanoseconds. `p` is a fraction (0.95 for p95).
///
/// **Nearest-rank**: the smallest sample at or above which `p` of the data lies —
/// `sorted[ceil(p·N) − 1]`. Chosen over interpolation because a latency report should only ever
/// print a value that was actually observed; an interpolated p95 is a number no packet ever
/// experienced, which invites arguing with the measurement instead of the system.
pub fn percentile(sorted: &[u64], p: f64) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let n = sorted.len();
    let rank = (p.clamp(0.0, 1.0) * n as f64).ceil() as usize;
    sorted[rank.clamp(1, n) - 1]
}

/// Nanos since an arbitrary fixed origin, as a `u64` for the wire. Monotonic within a process.
pub fn now_nanos(origin: Instant) -> u64 {
    origin.elapsed().as_nanos() as u64
}

/// Human-readable bytes/sec, sized to the number so a report is scannable.
pub fn fmt_bps(bps: f64) -> String {
    if bps >= 1024.0 * 1024.0 {
        format!("{:.2} MiB/s ({:.1} Mbps)", bps / 1048576.0, bps * 8.0 / 1e6)
    } else if bps >= 1024.0 {
        format!("{:.1} KiB/s ({:.2} Mbps)", bps / 1024.0, bps * 8.0 / 1e6)
    } else {
        format!("{bps:.0} B/s")
    }
}

pub fn fmt_ms(nanos: u64) -> String {
    format!("{:.2}ms", nanos as f64 / 1e6)
}

/// Send with a bounded, non-fatal error path. A load generator must never abort a 60-second run
/// because one datagram hit a transient `ENOBUFS`; the drop is the measurement.
pub fn send_lossy(sock: &UdpSocket, buf: &[u8]) -> bool {
    sock.send(buf).is_ok()
}

// ---------------------------------------------------------------------------
// Minimal argv parsing (zero-dep by design — see module docs)
// ---------------------------------------------------------------------------

/// `--key value` / `--flag` parser over `std::env::args`. Unknown keys are *rejected* rather than
/// ignored, so a typo in a rate flag fails the run instead of quietly measuring the default.
pub struct Args {
    pairs: Vec<(String, Option<String>)>,
}

impl Args {
    pub fn parse() -> Self {
        let mut pairs = Vec::new();
        let argv: Vec<String> = std::env::args().skip(1).collect();
        let mut i = 0;
        while i < argv.len() {
            let a = argv[i].clone();
            if let Some(key) = a.strip_prefix("--") {
                let val = argv.get(i + 1).filter(|v| !v.starts_with("--")).cloned();
                if val.is_some() {
                    i += 1;
                }
                pairs.push((key.to_string(), val));
            }
            i += 1;
        }
        Self { pairs }
    }

    pub fn get(&self, key: &str) -> Option<&str> {
        self.pairs
            .iter()
            .find(|(k, _)| k == key)
            .and_then(|(_, v)| v.as_deref())
    }

    pub fn flag(&self, key: &str) -> bool {
        self.pairs.iter().any(|(k, _)| k == key)
    }

    pub fn num<T: std::str::FromStr>(&self, key: &str, default: T) -> T {
        match self.get(key) {
            Some(v) => v.parse().unwrap_or_else(|_| {
                eprintln!("bad value for --{key}: {v:?}");
                std::process::exit(2);
            }),
            None => default,
        }
    }

    /// Reject any flag the binary doesn't know about.
    pub fn reject_unknown(&self, known: &[&str]) {
        for (k, _) in &self.pairs {
            if !known.contains(&k.as_str()) {
                eprintln!("unknown flag --{k}");
                std::process::exit(2);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn header_roundtrips() {
        let mut buf = [0u8; 64];
        let h = Header {
            kind: Kind::Down,
            class: Class::Video,
            seq: 4242,
            stamp: 999_999_999,
        };
        put_header(&mut buf, h);
        let got = parse_header(&buf).expect("parses");
        assert_eq!(got.kind, Kind::Down);
        assert_eq!(got.class, Class::Video);
        assert_eq!(got.seq, 4242);
        assert_eq!(got.stamp, 999_999_999);
    }

    #[test]
    fn foreign_datagram_is_rejected_not_guessed() {
        assert!(parse_header(&[0u8; 64]).is_none());
        assert!(parse_header(&[1, 2, 3]).is_none());
    }

    #[test]
    fn join_profile_clamps_hostile_rates() {
        let mut body = [0u8; JOIN_BODY_LEN];
        JoinProfile {
            v_pps: u32::MAX,
            v_bytes: u16::MAX,
            a_pps: u32::MAX,
            a_bytes: 1,
        }
        .encode(&mut body);
        let p = JoinProfile::decode(&body).expect("decodes");
        assert_eq!(p.v_pps, 200_000);
        assert_eq!(p.v_bytes, MAX_DATAGRAM as u16);
        // A sub-header size is raised to the header length, never left to underflow the padding.
        assert_eq!(p.a_bytes, HDR_LEN as u16);
    }

    #[test]
    fn loss_is_span_based_and_reorder_is_not_loss() {
        let mut s = SeriesStats::default();
        // seq 0,2,1 — one reorder, zero loss across the span.
        s.record(0, 100, 0, 1_000);
        s.record(2, 100, 100, 2_000);
        s.record(1, 100, 200, 3_000);
        assert_eq!(s.expected(), 3);
        assert_eq!(s.lost(), 0);
        assert_eq!(s.reordered, 1);

        // A genuine gap: 0,1,5 → span 6, received 3, lost 3.
        let mut g = SeriesStats::default();
        g.record(0, 100, 0, 0);
        g.record(1, 100, 0, 0);
        g.record(5, 100, 0, 0);
        assert_eq!(g.lost(), 3);
        assert!((g.loss_pct() - 50.0).abs() < 1e-9);
    }

    #[test]
    fn percentiles_pick_expected_samples() {
        let v: Vec<u64> = (1..=100).collect();
        assert_eq!(percentile(&v, 0.5), 50);
        assert_eq!(percentile(&v, 0.95), 95);
        assert_eq!(percentile(&v, 1.0), 100);
        assert_eq!(percentile(&[], 0.5), 0);
    }

    #[test]
    fn offered_bps_matches_hand_math() {
        // 9 fan-out video streams at 1500kbps in 1200B packets + audio.
        let p = JoinProfile {
            v_pps: 1406,
            v_bytes: 1200,
            a_pps: 450,
            a_bytes: 160,
        };
        assert_eq!(p.offered_bps(), 1406 * 1200 + 450 * 160);
    }
}
