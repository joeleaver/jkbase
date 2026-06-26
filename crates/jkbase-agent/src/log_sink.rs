//! The agent's single shared log buffer + cursor source.
//!
//! Every line the host shipper pulls from `GET /_jkbase/logs` is addressed by the
//! pair `(boot_id, seq)`: `boot_id` identifies this agent process incarnation and
//! `seq` is a monotonic per-boot counter. The host dedups on that pair, so there
//! MUST be exactly ONE `seq` source and ONE `boot_id` per agent process — two
//! independent `seq` spaces sharing a `boot_id` would alias each other and the
//! shipper would silently drop the collisions.
//!
//! That invariant is why this lives here and not inside `ContainerSupervisor`:
//! both the server supervisor (app stdout/stderr) and the function runtime (the
//! coming egress-observe manifest, `stream == "egress"`) write into the *same*
//! sink, handed to each as one process-wide `Arc<LogSink>` constructed in `main`.
//! P0-OBS-UNIFIED-SINK: if the manifest used a second `seq` space its rows would
//! collide the shipper cursor and the egress audit trail would fail **open**
//! (unobserved egress while the operator believes it is observed).

use jkbase_common::logs::{EGRESS_STREAM, EgressEvent, LogLine, Verdict};
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

/// Ring-buffer cap. Bounds the agent's resident log memory; the host shipper
/// pulls continuously so eviction only loses lines the host never polled.
const MAX_LOG_LINES: usize = 1000;

/// Separate, independently-bounded cap for egress events (P0-DOS-EGRESS-EVENT-BUFFER): a
/// function spraying (even *denied*) egress events must not evict the project's own app
/// logs — nor, under the exact flood you most want recorded, its own audit trail. Coalescing
/// (below) means a tight loop is one row + count, so this many DISTINCT destinations are
/// retained.
const MAX_EGRESS_LINES: usize = 512;

/// How many recent rows `push_egress` scans to coalesce a repeat. Coalescing only against
/// the tail (the naive approach) lets interleaved distinct tuples (`A,B,A,B,…`) overrun the
/// ring (review L-1); a bounded recent window collapses them without an O(n) scan per push.
const EGRESS_COALESCE_WINDOW: usize = 128;

/// Synthetic `dest_host` for the overflow marker row that records how many egress rows were
/// evicted under a flood, so the existence-of-flood signal survives even when individual
/// (attack-noise) deny rows are dropped (review M-2/L-1).
const EGRESS_DROPPED_MARKER_HOST: &str = "(egress-events-dropped)";

/// A buffered egress event with its assigned cursor position. Kept as the typed struct (not
/// a pre-serialized `LogLine`) so repeated identical events coalesce in place.
struct EgressLine {
    seq: u64,
    timestamp: u64,
    event: EgressEvent,
}

/// The egress ring plus an overflow accountant. The ring is bounded; when it overflows we
/// prefer to evict a DENY row over an ALLOW row, so a function spraying denied destinations
/// can never suppress a buffered ALLOW contact (the real exfil destination it most wants
/// hidden — P0-OBS-UNCONDITIONAL). Evictions bump `dropped`, surfaced as one marker row.
#[derive(Default)]
struct EgressBuf {
    ring: VecDeque<EgressLine>,
    /// Count of egress rows evicted under overflow (attack noise), surfaced as a marker.
    dropped: u64,
    /// Stable cursor seq for the dropped-marker row, allocated once on the first eviction
    /// (0 = none yet). Its `count` grows while `seq` stays fixed — advisory, like coalescing.
    dropped_seq: u64,
}

/// Shared, bounded log buffer plus the monotonic sequence source the host shipper
/// uses as a cursor. Shared process-wide via `Arc<LogSink>`; the interior
/// `Mutex`/`AtomicU64` provide the synchronization, so it is NOT `Clone` — clone
/// the `Arc`, never the buffer.
pub struct LogSink {
    buffer: Mutex<VecDeque<LogLine>>,
    /// Egress events — a SEPARATE bounded buffer (eviction here can't drop app logs and vice
    /// versa) sharing the ONE `seq` source below so the host's `(boot_id, seq)` cursor stays
    /// a single ordered space across both (P0-OBS-UNIFIED-SINK).
    egress: Mutex<EgressBuf>,
    seq: AtomicU64,
    /// Identifies this agent process incarnation. Stable across snapshot restore
    /// (the in-memory buffer survives the freeze), regenerated on cold boot — which
    /// is how the host shipper detects that the `seq` counter has reset.
    boot_id: String,
}

impl LogSink {
    pub fn new() -> Self {
        Self {
            buffer: Mutex::new(VecDeque::with_capacity(MAX_LOG_LINES)),
            egress: Mutex::new(EgressBuf::default()),
            seq: AtomicU64::new(0),
            boot_id: generate_boot_id(),
        }
    }

    pub fn boot_id(&self) -> &str {
        &self.boot_id
    }

    /// Append a line, assigning it the next `seq`. Evicts the oldest line once the
    /// ring is full.
    pub async fn push(&self, server: &str, stream: &str, line: String) {
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        let mut buf = self.buffer.lock().await;
        if buf.len() >= MAX_LOG_LINES {
            buf.pop_front();
        }
        buf.push_back(LogLine {
            server: server.to_string(),
            stream: stream.to_string(),
            line,
            timestamp: now_secs(),
            seq,
        });
    }

    /// Record a function egress decision into the reserved `stream == "egress"` channel.
    /// Host-only (the guest output drains never call this), so a guest cannot forge or bury
    /// egress rows (P0-OBS-STREAM-RESERVED).
    ///
    /// Coalesces a repeat of any of the recent `(function, dest_host, dest_port, verdict)`
    /// rows (not just the tail — review L-1) into that row (bump `count`, fold the advisory
    /// bytes), so a tight or interleaved allow/deny loop is a few rows + counts, not N
    /// (P0-DOS-EGRESS-EVENT-BUFFER). On overflow, a DENY row is evicted in preference to an
    /// ALLOW row, so a deny-flood can never suppress a buffered ALLOW contact (the real
    /// destination — review M-2 / P0-OBS-UNCONDITIONAL); evictions are tallied into a marker.
    /// Coalesced/marker rows keep their original `seq` (the host may already have pulled it;
    /// the count is advisory).
    pub async fn push_egress(&self, mut event: EgressEvent) {
        if event.count == 0 {
            event.count = 1;
        }
        let mut eb = self.egress.lock().await;
        // Windowed coalescing: scan the most recent rows for a matching key.
        let start = eb.ring.len().saturating_sub(EGRESS_COALESCE_WINDOW);
        if let Some(existing) = eb.ring.iter_mut().skip(start).find(|e| {
            e.event.function == event.function
                && e.event.dest_host == event.dest_host
                && e.event.dest_port == event.dest_port
                && e.event.verdict == event.verdict
        }) {
            existing.event.count = existing.event.count.saturating_add(event.count);
            existing.event.bytes_out = existing.event.bytes_out.saturating_add(event.bytes_out);
            existing.event.bytes_in = existing.event.bytes_in.saturating_add(event.bytes_in);
            if event.status.is_some() {
                existing.event.status = event.status;
            }
            if event.dest_ip.is_some() {
                existing.event.dest_ip = event.dest_ip;
            }
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if eb.ring.len() >= MAX_EGRESS_LINES {
            // Evict the OLDEST non-allow row; only fall back to the front if the ring is all
            // allows (then a genuine many-distinct-allow contact set, evict oldest).
            let idx = eb
                .ring
                .iter()
                .position(|e| e.event.verdict != Verdict::Allow)
                .unwrap_or(0);
            eb.ring.remove(idx);
            eb.dropped = eb.dropped.saturating_add(1);
            if eb.dropped_seq == 0 {
                eb.dropped_seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
            }
        }
        eb.ring.push_back(EgressLine {
            seq,
            timestamp: now_secs(),
            event,
        });
    }

    /// Collect the egress ring as `LogLine`s, plus the dropped-marker row if any rows were
    /// evicted (so a flood that drops attack-noise denies still leaves a visible signal).
    fn egress_lines(eb: &EgressBuf) -> Vec<LogLine> {
        let mut out: Vec<LogLine> = eb.ring.iter().map(Self::egress_line).collect();
        if eb.dropped > 0 {
            let marker = EgressEvent {
                function: "_egress".to_string(),
                dest_host: EGRESS_DROPPED_MARKER_HOST.to_string(),
                dest_port: 0,
                dest_ip: None,
                verdict: Verdict::Error,
                method: String::new(),
                count: eb.dropped,
                bytes_out: 0,
                bytes_in: 0,
                status: None,
            };
            out.push(LogLine {
                server: "_egress".to_string(),
                stream: EGRESS_STREAM.to_string(),
                line: serde_json::to_string(&marker).unwrap_or_default(),
                timestamp: now_secs(),
                seq: eb.dropped_seq,
            });
        }
        out
    }

    /// Render one buffered egress event as a `LogLine` (reserved `stream`, JSON body).
    fn egress_line(e: &EgressLine) -> LogLine {
        LogLine {
            server: e.event.function.clone(),
            stream: EGRESS_STREAM.to_string(),
            line: serde_json::to_string(&e.event).unwrap_or_default(),
            timestamp: e.timestamp,
            seq: e.seq,
        }
    }

    /// Return the most recent `limit` buffered lines (tail), merging app output + egress
    /// events in `seq` order.
    pub async fn get_logs(&self, limit: usize) -> Vec<LogLine> {
        let mut merged: Vec<LogLine> = {
            let buf = self.buffer.lock().await;
            let egress = self.egress.lock().await;
            buf.iter()
                .cloned()
                .chain(Self::egress_lines(&egress))
                .collect()
        };
        merged.sort_by_key(|l| l.seq);
        let start = merged.len().saturating_sub(limit);
        merged.split_off(start)
    }

    /// Return all buffered lines (app output + egress events) with `seq` strictly greater
    /// than `since`, in `seq` order — the host shipper's incremental cursor.
    pub async fn get_logs_since(&self, since: u64) -> Vec<LogLine> {
        let mut merged: Vec<LogLine> = {
            let buf = self.buffer.lock().await;
            let egress = self.egress.lock().await;
            buf.iter()
                .filter(|l| l.seq > since)
                .cloned()
                .chain(
                    Self::egress_lines(&egress)
                        .into_iter()
                        .filter(|l| l.seq > since),
                )
                .collect()
        };
        merged.sort_by_key(|l| l.seq);
        merged
    }
}

impl Default for LogSink {
    fn default() -> Self {
        Self::new()
    }
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

fn generate_boot_id() -> String {
    // Nanosecond timestamp + pid is enough to distinguish process incarnations.
    // (It need not be globally unique, only different across cold boots of one VM.)
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or_default();
    format!("{nanos:x}-{}", std::process::id())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn seq_increments_and_since_filters() {
        let sink = LogSink::new();
        sink.push("web", "stdout", "a".into()).await;
        sink.push("web", "stdout", "b".into()).await;
        sink.push("web", "stderr", "c".into()).await;

        let all = sink.get_logs(10).await;
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[2].seq, 3);

        let since1 = sink.get_logs_since(1).await;
        assert_eq!(since1.len(), 2);
        assert_eq!(since1[0].line, "b");
        assert!(sink.get_logs_since(3).await.is_empty());
    }

    #[tokio::test]
    async fn buffer_evicts_oldest_but_seq_keeps_climbing() {
        let sink = LogSink::new();
        for i in 0..(MAX_LOG_LINES + 50) {
            sink.push("web", "stdout", format!("line{i}")).await;
        }
        let all = sink.get_logs(MAX_LOG_LINES * 2).await;
        assert_eq!(all.len(), MAX_LOG_LINES);
        // The oldest 50 were evicted, but `seq` reflects total pushes — never wraps,
        // so the host cursor (which compares seq) never confuses eviction for "no new
        // logs" nor a wrap-around for a reset.
        assert_eq!(all.last().unwrap().seq as usize, MAX_LOG_LINES + 50);
        let recent = sink.get_logs_since((MAX_LOG_LINES + 48) as u64).await;
        assert_eq!(recent.len(), 2);
    }

    #[test]
    fn boot_id_is_stable_per_instance() {
        let sink = LogSink::new();
        assert_eq!(sink.boot_id(), sink.boot_id());
        assert!(!sink.boot_id().is_empty());
    }

    fn ev(host: &str, verdict: Verdict) -> EgressEvent {
        EgressEvent {
            function: "fn".into(),
            dest_host: host.into(),
            dest_port: 443,
            dest_ip: None,
            verdict,
            method: "GET".into(),
            count: 1,
            bytes_out: 0,
            bytes_in: 0,
            status: None,
        }
    }

    #[tokio::test]
    async fn egress_coalesces_repeats_and_shares_one_cursor() {
        let sink = LogSink::new();
        // App line first (seq 1), then a tight deny loop to the same dest, then a distinct dest.
        sink.push("web", "stdout", "boot".into()).await;
        for _ in 0..5 {
            sink.push_egress(ev("evil.example", Verdict::DenySandbox))
                .await;
        }
        sink.push_egress(ev("api.stripe.com", Verdict::Allow)).await;

        let all = sink.get_logs(100).await;
        // 1 app line + 2 egress rows (the 5 evil hits coalesced into one).
        let egress: Vec<&LogLine> = all.iter().filter(|l| l.stream == EGRESS_STREAM).collect();
        assert_eq!(egress.len(), 2, "repeats must coalesce to one row");
        let evil: EgressEvent = serde_json::from_str(
            &egress
                .iter()
                .find(|l| l.line.contains("evil"))
                .unwrap()
                .line,
        )
        .unwrap();
        assert_eq!(evil.count, 5, "coalesced count");
        // Unified, strictly-increasing cursor across app + egress streams.
        let seqs: Vec<u64> = all.iter().map(|l| l.seq).collect();
        let mut sorted = seqs.clone();
        sorted.sort_unstable();
        assert_eq!(seqs, sorted, "merged output is seq-ordered");
        assert_eq!(all.first().unwrap().line, "boot", "app line keeps seq 1");

        // since-cursor returns only newer rows from BOTH buffers.
        let after_first = sink.get_logs_since(all[0].seq).await;
        assert!(after_first.iter().all(|l| l.stream == EGRESS_STREAM));
    }

    #[tokio::test]
    async fn deny_flood_cannot_evict_a_buffered_allow() {
        // M-2: one real Allow contact, then a flood of DISTINCT denied destinations that
        // overruns the ring. The Allow row (the real exfil destination) must survive, and a
        // dropped-marker must record that a flood happened.
        let sink = LogSink::new();
        sink.push_egress(ev("real-exfil.example", Verdict::Allow))
            .await;
        for i in 0..(MAX_EGRESS_LINES + 200) {
            // distinct host each time → never coalesces → forces eviction
            sink.push_egress(ev(&format!("d{i}.evil"), Verdict::DenyPlatform))
                .await;
        }

        let all = sink.get_logs(100_000).await;
        let events: Vec<EgressEvent> = all
            .iter()
            .filter(|l| l.stream == EGRESS_STREAM)
            .filter_map(|l| serde_json::from_str(&l.line).ok())
            .collect();
        assert!(
            events
                .iter()
                .any(|e| e.verdict == Verdict::Allow && e.dest_host == "real-exfil.example"),
            "the buffered Allow contact must survive a distinct-deny flood"
        );
        assert!(
            events
                .iter()
                .any(|e| e.dest_host == EGRESS_DROPPED_MARKER_HOST && e.count > 0),
            "a dropped-marker must record the flood overflow"
        );
        // The ring stays bounded (plus the one marker row).
        assert!(events.len() <= MAX_EGRESS_LINES + 1);
    }

    #[tokio::test]
    async fn egress_coalesces_against_a_recent_window_not_just_the_tail() {
        // L-1: interleaved A,B,A,B must collapse to 2 rows, not 4.
        let sink = LogSink::new();
        for _ in 0..4 {
            sink.push_egress(ev("a.example", Verdict::Allow)).await;
            sink.push_egress(ev("b.example", Verdict::Allow)).await;
        }
        let all = sink.get_logs(100).await;
        let egress: Vec<&LogLine> = all.iter().filter(|l| l.stream == EGRESS_STREAM).collect();
        assert_eq!(
            egress.len(),
            2,
            "interleaved repeats coalesce within the window"
        );
    }
}
