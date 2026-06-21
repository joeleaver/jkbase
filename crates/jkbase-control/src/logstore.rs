//! Persistent, per-project log storage on the host.
//!
//! Guest-agent/container logs are shipped here by the server's log shipper so they
//! survive VM hibernation, restart, and crashes — the in-VM ring buffer only holds
//! the last ~1000 lines and is lost when the microVM goes away.
//!
//! Storage is append-only JSONL, one directory per project, with size-based
//! rotation and a fixed retention window. Keeping logs out of the control redb
//! is deliberate: under the all-tenants-untrusted threat model a tenant can emit
//! arbitrary log volume, and we don't want that to bloat or contend the database
//! that holds projects, auth, and allocations. Each project's on-disk footprint
//! is hard-bounded by `MAX_FILE_BYTES * (MAX_ROTATED + 1)`.
//!
//! Each persisted line carries a store-assigned, per-project monotonic `seq`
//! (overwriting the agent-side seq, which is only meaningful host→agent). That
//! store seq is the cursor the CLI uses to tail logs incrementally — unlike the
//! agent seq it does not reset across guest cold boots.

use anyhow::Result;
use jkbase_common::logs::{LogLine, EGRESS_STREAM};
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Rotate the active log file once it reaches this size.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
/// Number of rotated files to retain per project (`app.log.1` .. `app.log.N`).
const MAX_ROTATED: usize = 3;

/// Egress audit events (`stream == "egress"`) are stored in a SEPARATE file set with an
/// INDEPENDENT retention budget, so a tenant flooding ordinary app logs cannot rotate its
/// own (or the operator's) egress-audit rows off disk (adversarial-review H-1; the durable
/// counterpart of the in-VM separate buffer, P0-OBS-UNCONDITIONAL / P0-DOS-EGRESS-EVENT-
/// BUFFER). Events are small, coalesced, and rate-limited at the agent, so a generous
/// rotated-file count buys a long (≥weeks) window at a small footprint. Read-side merges
/// app + egress by the unified store seq, so the CLI sees one ordered stream.
const EGRESS_MAX_FILE_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
const EGRESS_MAX_ROTATED: usize = 11; // ~60 MiB egress budget, independent of app logs

#[derive(Default)]
struct ProjectState {
    /// Next store seq to assign for this project.
    next_seq: u64,
    /// Whether `next_seq` has been initialized from disk.
    initialized: bool,
}

/// Append-only per-project log store. Cheap to clone (shares one lock).
#[derive(Clone)]
pub struct LogStore {
    inner: std::sync::Arc<Inner>,
}

struct Inner {
    root: PathBuf,
    /// Single lock guarding all mutating and reading operations. Log volume is
    /// modest and reads are infrequent (CLI requests), so global serialization
    /// keeps the implementation simple and correct (no torn appends/rotations).
    state: Mutex<HashMap<String, ProjectState>>,
}

impl LogStore {
    pub fn new(root: PathBuf) -> Self {
        Self {
            inner: std::sync::Arc::new(Inner {
                root,
                state: Mutex::new(HashMap::new()),
            }),
        }
    }

    fn project_dir(&self, project_id: &str) -> PathBuf {
        self.inner.root.join(sanitize(project_id))
    }

    /// Append shipped lines for a project, assigning each a store-side seq.
    pub fn append(&self, project_id: &str, lines: &[LogLine]) -> Result<()> {
        if lines.is_empty() {
            return Ok(());
        }

        let dir = self.project_dir(project_id);
        std::fs::create_dir_all(&dir)?;

        let mut guard = self.inner.state.lock().unwrap();
        let st = guard.entry(project_id.to_string()).or_default();
        if !st.initialized {
            st.next_seq = highest_seq_on_disk(&dir);
            st.initialized = true;
        }

        // Assign the unified per-project seq in arrival order, then PARTITION by stream into
        // two independently-retained file sets (app vs egress) so an app-log flood cannot
        // evict the egress audit trail. Both share the seq space → read-side merges them.
        let mut app_buf = String::with_capacity(lines.len() * 128);
        let mut egr_buf = String::new();
        for line in lines {
            st.next_seq += 1;
            let stored = LogLine {
                seq: st.next_seq,
                ..line.clone()
            };
            let target = if line.stream == EGRESS_STREAM {
                &mut egr_buf
            } else {
                &mut app_buf
            };
            target.push_str(&serde_json::to_string(&stored)?);
            target.push('\n');
        }

        append_stream(&dir, "app.log", &app_buf, MAX_FILE_BYTES, MAX_ROTATED)?;
        append_stream(&dir, "egress.log", &egr_buf, EGRESS_MAX_FILE_BYTES, EGRESS_MAX_ROTATED)?;
        Ok(())
    }

    /// Read persisted log lines for a project.
    ///
    /// - `since == Some(seq)`: return every retained line with store seq > `seq`
    ///   (for incremental tailing), bounded only by the retention window.
    /// - `since == None`: return the most recent `limit` lines.
    ///
    /// `service` optionally filters by server name. Lines are returned oldest first.
    pub fn read(
        &self,
        project_id: &str,
        limit: usize,
        service: Option<&str>,
        since: Option<u64>,
    ) -> Result<Vec<LogLine>> {
        let dir = self.project_dir(project_id);
        let _guard = self.inner.state.lock().unwrap();

        let mut all: Vec<LogLine> = Vec::new();
        // Oldest rotated file first, active file last → chronological order.
        for i in (1..=MAX_ROTATED).rev() {
            read_lines_into(&dir.join(format!("app.log.{i}")), &mut all);
        }
        read_lines_into(&dir.join("app.log"), &mut all);
        // Merge in the separately-retained egress audit stream, then sort by the unified
        // store seq so the two streams interleave in chronological order.
        for i in (1..=EGRESS_MAX_ROTATED).rev() {
            read_lines_into(&dir.join(format!("egress.log.{i}")), &mut all);
        }
        read_lines_into(&dir.join("egress.log"), &mut all);
        all.sort_by_key(|l| l.seq);

        if let Some(svc) = service {
            all.retain(|l| l.server == svc);
        }

        match since {
            Some(s) => {
                all.retain(|l| l.seq > s);
                Ok(all)
            }
            None => {
                let start = all.len().saturating_sub(limit);
                Ok(all.split_off(start))
            }
        }
    }

    /// Remove all persisted logs for a project (called on project deletion).
    pub fn clear(&self, project_id: &str) -> Result<()> {
        let dir = self.project_dir(project_id);
        let mut guard = self.inner.state.lock().unwrap();
        guard.remove(project_id);
        if dir.exists() {
            std::fs::remove_dir_all(&dir)?;
        }
        Ok(())
    }
}

fn file_len(path: &Path) -> u64 {
    std::fs::metadata(path).map(|m| m.len()).unwrap_or(0)
}

/// Append `buf` to `dir/{base}`, rotating that base's file set first if the active file is
/// already at `max_bytes`. No-op on an empty buffer. Each stream (app/egress) rotates
/// independently, which is the whole point of H-1: app churn never touches egress files.
fn append_stream(dir: &Path, base: &str, buf: &str, max_bytes: u64, max_rotated: usize) -> Result<()> {
    if buf.is_empty() {
        return Ok(());
    }
    let active = dir.join(base);
    if file_len(&active) >= max_bytes {
        rotate(dir, base, max_rotated)?;
    }
    let mut f = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&active)?;
    f.write_all(buf.as_bytes())?;
    Ok(())
}

/// Shift `{base}` -> `{base}.1` -> ... dropping the oldest, leaving no active `{base}`.
fn rotate(dir: &Path, base: &str, max_rotated: usize) -> Result<()> {
    let oldest = dir.join(format!("{base}.{max_rotated}"));
    if oldest.exists() {
        std::fs::remove_file(&oldest)?;
    }
    for i in (1..max_rotated).rev() {
        let from = dir.join(format!("{base}.{i}"));
        let to = dir.join(format!("{base}.{}", i + 1));
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    let active = dir.join(base);
    if active.exists() {
        std::fs::rename(&active, dir.join(format!("{base}.1")))?;
    }
    Ok(())
}

fn read_lines_into(path: &Path, out: &mut Vec<LogLine>) {
    let Ok(file) = std::fs::File::open(path) else {
        return;
    };
    let reader = std::io::BufReader::new(file);
    for line in reader.lines().map_while(Result::ok) {
        if line.is_empty() {
            continue;
        }
        if let Ok(entry) = serde_json::from_str::<LogLine>(&line) {
            out.push(entry);
        }
    }
}

/// Determine the highest store seq already persisted for a project so a fresh process
/// continues numbering monotonically. The seq is unified across both streams, so consider
/// the newest line of each active file (and its first rotation, in case it was just rotated
/// empty).
fn highest_seq_on_disk(dir: &Path) -> u64 {
    last_seq(&dir.join("app.log"))
        .max(last_seq(&dir.join("app.log.1")))
        .max(last_seq(&dir.join("egress.log")))
        .max(last_seq(&dir.join("egress.log.1")))
}

fn last_seq(path: &Path) -> u64 {
    let mut lines = Vec::new();
    read_lines_into(path, &mut lines);
    lines.last().map(|l| l.seq).unwrap_or(0)
}

/// Restrict a project id to a safe path component (defense in depth against
/// traversal even though ids are server-generated slugs).
fn sanitize(project_id: &str) -> String {
    let s: String = project_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '-'
            }
        })
        .collect();
    if s.is_empty() {
        "_".to_string()
    } else {
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn line(server: &str, msg: &str) -> LogLine {
        LogLine {
            server: server.to_string(),
            stream: "stdout".to_string(),
            line: msg.to_string(),
            timestamp: 0,
            seq: 0,
        }
    }

    fn egress_line(msg: &str) -> LogLine {
        LogLine {
            server: "fn".to_string(),
            stream: EGRESS_STREAM.to_string(),
            line: msg.to_string(),
            timestamp: 0,
            seq: 0,
        }
    }

    fn tmp_root() -> PathBuf {
        let mut p = std::env::temp_dir();
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        p.push(format!("jkbase-logstore-test-{nanos}"));
        p
    }

    #[test]
    fn append_and_read_tail() {
        let root = tmp_root();
        let store = LogStore::new(root.clone());
        store
            .append("proj", &[line("web", "a"), line("web", "b")])
            .unwrap();
        store.append("proj", &[line("web", "c")]).unwrap();

        let all = store.read("proj", 100, None, None).unwrap();
        assert_eq!(all.len(), 3);
        assert_eq!(all[0].line, "a");
        assert_eq!(all[2].line, "c");
        // Store assigns monotonic seq regardless of incoming seq.
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[2].seq, 3);

        let tail = store.read("proj", 2, None, None).unwrap();
        assert_eq!(tail.len(), 2);
        assert_eq!(tail[0].line, "b");

        store.clear("proj").unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn read_since_cursor_and_service_filter() {
        let root = tmp_root();
        let store = LogStore::new(root.clone());
        store
            .append("p", &[line("web", "1"), line("db", "2"), line("web", "3")])
            .unwrap();

        let since1 = store.read("p", 100, None, Some(1)).unwrap();
        assert_eq!(since1.len(), 2);
        assert_eq!(since1[0].line, "2");

        let web = store.read("p", 100, Some("web"), None).unwrap();
        assert_eq!(web.len(), 2);
        assert!(web.iter().all(|l| l.server == "web"));

        store.clear("p").unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn seq_persists_across_store_reopen() {
        let root = tmp_root();
        {
            let store = LogStore::new(root.clone());
            store.append("p", &[line("web", "a")]).unwrap();
        }
        // New LogStore instance (simulating a server restart) must continue the
        // seq from disk rather than restarting at 1.
        let store2 = LogStore::new(root.clone());
        store2.append("p", &[line("web", "b")]).unwrap();
        let all = store2.read("p", 100, None, None).unwrap();
        assert_eq!(all.len(), 2);
        assert_eq!(all[0].seq, 1);
        assert_eq!(all[1].seq, 2);

        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn egress_audit_survives_an_app_log_flood() {
        // H-1: a tenant makes one real egress (audit) call, then floods app logs. The
        // egress row must survive — it lives in a separately-retained file set that app
        // churn never rotates.
        let root = tmp_root();
        let store = LogStore::new(root.clone());
        store.append("p", &[egress_line("{\"dest_host\":\"c2.evil\"}")]).unwrap();

        let big = "x".repeat(64 * 1024);
        for i in 0..400 {
            store.append("p", &[line("web", &format!("{i}:{big}"))]).unwrap();
        }

        // App logs rotated hard (oldest gone), but the egress row is still readable.
        let all = store.read("p", 100_000, None, None).unwrap();
        let egress: Vec<&LogLine> = all.iter().filter(|l| l.stream == EGRESS_STREAM).collect();
        assert_eq!(egress.len(), 1, "the egress audit row must survive the app-log flood");
        assert!(egress[0].line.contains("c2.evil"));
        assert_eq!(egress[0].seq, 1, "it kept its unified seq and read-merges in order");
        // Sanity: the app flood DID rotate (oldest app lines gone).
        let app: Vec<&LogLine> = all.iter().filter(|l| l.stream != EGRESS_STREAM).collect();
        assert!(app.iter().all(|l| !l.line.starts_with("0:")), "oldest app lines rotated off");

        store.clear("p").unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn rotation_bounds_files_and_preserves_recent() {
        let root = tmp_root();
        let store = LogStore::new(root.clone());
        // Write enough large lines to force several rotations.
        let big = "x".repeat(64 * 1024);
        for i in 0..400 {
            store
                .append("p", &[line("web", &format!("{i}:{big}"))])
                .unwrap();
        }

        let dir = root.join("p");
        // app.log plus at most MAX_ROTATED rotated files.
        assert!(!dir.join(format!("app.log.{}", MAX_ROTATED + 1)).exists());

        // Most recent line must still be retrievable and seq keeps climbing.
        let tail = store.read("p", 1, None, None).unwrap();
        assert_eq!(tail.len(), 1);
        assert!(tail[0].line.starts_with("399:"));
        assert_eq!(tail[0].seq, 400);

        store.clear("p").unwrap();
        let _ = std::fs::remove_dir_all(&root);
    }
}
