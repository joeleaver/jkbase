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

use jkbase_common::logs::{EgressEvent, LogLine, EGRESS_STREAM};
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

/// A buffered egress event with its assigned cursor position. Kept as the typed struct (not
/// a pre-serialized `LogLine`) so repeated identical events coalesce in place.
struct EgressLine {
    seq: u64,
    timestamp: u64,
    event: EgressEvent,
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
    egress: Mutex<VecDeque<EgressLine>>,
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
            egress: Mutex::new(VecDeque::with_capacity(MAX_EGRESS_LINES)),
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
    /// egress rows (P0-OBS-STREAM-RESERVED). Coalesces a repeat of the most-recent
    /// `(function, dest_host, dest_port, verdict)` into that row (bump `count`, fold the
    /// advisory bytes) instead of appending — so a tight allow/deny loop is ONE row + count,
    /// not N (P0-DOS-EGRESS-EVENT-BUFFER). The coalesced row keeps its original `seq` (the
    /// host may already have pulled it; the count is advisory).
    pub async fn push_egress(&self, mut event: EgressEvent) {
        if event.count == 0 {
            event.count = 1;
        }
        let mut buf = self.egress.lock().await;
        if let Some(tail) = buf.back_mut()
            && tail.event.function == event.function
            && tail.event.dest_host == event.dest_host
            && tail.event.dest_port == event.dest_port
            && tail.event.verdict == event.verdict
        {
            tail.event.count = tail.event.count.saturating_add(event.count);
            tail.event.bytes_out = tail.event.bytes_out.saturating_add(event.bytes_out);
            tail.event.bytes_in = tail.event.bytes_in.saturating_add(event.bytes_in);
            if event.status.is_some() {
                tail.event.status = event.status;
            }
            if event.dest_ip.is_some() {
                tail.event.dest_ip = event.dest_ip;
            }
            return;
        }
        let seq = self.seq.fetch_add(1, Ordering::Relaxed) + 1;
        if buf.len() >= MAX_EGRESS_LINES {
            buf.pop_front();
        }
        buf.push_back(EgressLine {
            seq,
            timestamp: now_secs(),
            event,
        });
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
            buf.iter().cloned().chain(egress.iter().map(Self::egress_line)).collect()
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
                    egress
                        .iter()
                        .filter(|e| e.seq > since)
                        .map(Self::egress_line),
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
    use jkbase_common::logs::Verdict;

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
            sink.push_egress(ev("evil.example", Verdict::DenySandbox)).await;
        }
        sink.push_egress(ev("api.stripe.com", Verdict::Allow)).await;

        let all = sink.get_logs(100).await;
        // 1 app line + 2 egress rows (the 5 evil hits coalesced into one).
        let egress: Vec<&LogLine> = all.iter().filter(|l| l.stream == EGRESS_STREAM).collect();
        assert_eq!(egress.len(), 2, "repeats must coalesce to one row");
        let evil: EgressEvent =
            serde_json::from_str(&egress.iter().find(|l| l.line.contains("evil")).unwrap().line)
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
}
