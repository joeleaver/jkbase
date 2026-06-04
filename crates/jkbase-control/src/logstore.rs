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
use jkbase_common::logs::LogLine;
use std::collections::HashMap;
use std::io::{BufRead, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

/// Rotate the active log file once it reaches this size.
const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024; // 5 MiB
/// Number of rotated files to retain per project (`app.log.1` .. `app.log.N`).
const MAX_ROTATED: usize = 3;

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
        let active = dir.join("app.log");

        let mut guard = self.inner.state.lock().unwrap();
        let st = guard.entry(project_id.to_string()).or_default();
        if !st.initialized {
            st.next_seq = highest_seq_on_disk(&dir);
            st.initialized = true;
        }

        // Rotate before writing if the active file is already at the threshold.
        if file_len(&active) >= MAX_FILE_BYTES {
            rotate(&dir)?;
        }

        let mut buf = String::with_capacity(lines.len() * 128);
        for line in lines {
            st.next_seq += 1;
            let stored = LogLine {
                seq: st.next_seq,
                ..line.clone()
            };
            buf.push_str(&serde_json::to_string(&stored)?);
            buf.push('\n');
        }

        let mut f = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&active)?;
        f.write_all(buf.as_bytes())?;
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

/// Shift `app.log` -> `app.log.1` -> ... dropping the oldest, leaving no `app.log`.
fn rotate(dir: &Path) -> Result<()> {
    let oldest = dir.join(format!("app.log.{MAX_ROTATED}"));
    if oldest.exists() {
        std::fs::remove_file(&oldest)?;
    }
    for i in (1..MAX_ROTATED).rev() {
        let from = dir.join(format!("app.log.{i}"));
        let to = dir.join(format!("app.log.{}", i + 1));
        if from.exists() {
            std::fs::rename(&from, &to)?;
        }
    }
    let active = dir.join("app.log");
    if active.exists() {
        std::fs::rename(&active, dir.join("app.log.1"))?;
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

/// Determine the highest store seq already persisted for a project so a fresh
/// process continues numbering monotonically. The active file holds the newest
/// lines; if it was just rotated and is empty, fall back to `app.log.1`.
fn highest_seq_on_disk(dir: &Path) -> u64 {
    last_seq(&dir.join("app.log")).max(last_seq(&dir.join("app.log.1")))
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
