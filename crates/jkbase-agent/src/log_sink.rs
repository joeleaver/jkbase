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

use jkbase_common::logs::LogLine;
use std::collections::VecDeque;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::sync::Mutex;

/// Ring-buffer cap. Bounds the agent's resident log memory; the host shipper
/// pulls continuously so eviction only loses lines the host never polled.
const MAX_LOG_LINES: usize = 1000;

/// Shared, bounded log buffer plus the monotonic sequence source the host shipper
/// uses as a cursor. Shared process-wide via `Arc<LogSink>`; the interior
/// `Mutex`/`AtomicU64` provide the synchronization, so it is NOT `Clone` — clone
/// the `Arc`, never the buffer.
pub struct LogSink {
    buffer: Mutex<VecDeque<LogLine>>,
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

    /// Return the most recent `limit` buffered lines (tail).
    pub async fn get_logs(&self, limit: usize) -> Vec<LogLine> {
        let buf = self.buffer.lock().await;
        let start = buf.len().saturating_sub(limit);
        buf.iter().skip(start).cloned().collect()
    }

    /// Return all buffered lines with `seq` strictly greater than `since` — the
    /// host shipper's incremental cursor.
    pub async fn get_logs_since(&self, since: u64) -> Vec<LogLine> {
        let buf = self.buffer.lock().await;
        buf.iter().filter(|l| l.seq > since).cloned().collect()
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
}
