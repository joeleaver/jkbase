//! Host-side log shipper.
//!
//! Periodically pulls new log lines from each running guest agent over HTTP and
//! appends them to the persistent [`LogStore`]. Pull (host-initiated) rather than
//! push keeps the trust boundary intact: the untrusted guest only ever responds,
//! it never reaches into the control plane.
//!
//! Deduplication uses a per-project cursor of `(agent boot_id, agent seq)`. The
//! agent assigns a monotonic seq per process incarnation and exposes a `boot_id`
//! that changes on cold boot. We fetch `?since=<seq>` so the agent returns only
//! new lines; when the `boot_id` changes (cold boot reset the seq counter) we
//! refetch the full buffer. Cursors are persisted to disk so a server restart
//! doesn't re-ship (and thus duplicate) a snapshot-restored agent's buffer.

use anyhow::Result;
use jkbase_common::logs::LogsResponse;
use jkbase_control::logstore::LogStore;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::Mutex;
use tracing::{debug, warn};

pub const POLL_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Serialize, Deserialize)]
struct Cursor {
    boot_id: String,
    seq: u64,
}

pub struct LogShipper {
    log_store: LogStore,
    cursor_path: PathBuf,
    cursors: Mutex<HashMap<String, Cursor>>,
    /// Per-project locks so the poll loop and the hibernate/redeploy final flush
    /// can't ship the same project concurrently (which would double-append).
    locks: Mutex<HashMap<String, Arc<Mutex<()>>>>,
}

impl LogShipper {
    pub fn new(log_store: LogStore, cursor_path: PathBuf) -> Arc<Self> {
        let cursors = load_cursors(&cursor_path);
        Arc::new(Self {
            log_store,
            cursor_path,
            cursors: Mutex::new(cursors),
            locks: Mutex::new(HashMap::new()),
        })
    }

    async fn project_lock(&self, project_id: &str) -> Arc<Mutex<()>> {
        let mut locks = self.locks.lock().await;
        locks
            .entry(project_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    /// Fetch and persist any new log lines from one running agent.
    /// Best-effort: transport errors are logged at debug and otherwise ignored
    /// (the next poll retries).
    pub async fn ship(&self, project_id: &str, ip: &str) {
        let lock = self.project_lock(project_id).await;
        let _guard = lock.lock().await;

        let (used_since, stored_boot) = {
            let cursors = self.cursors.lock().await;
            match cursors.get(project_id) {
                Some(c) => (c.seq, Some(c.boot_id.clone())),
                None => (0, None),
            }
        };

        let mut resp = match fetch_logs(ip, used_since).await {
            Ok(r) => r,
            Err(e) => {
                debug!(project = %project_id, ip, error = %e, "log fetch failed");
                return;
            }
        };

        // boot_id mismatch ⇒ the agent restarted and its seq counter reset, so the
        // `since` we sent referred to a previous incarnation. Refetch everything.
        let reset = stored_boot.as_deref() != Some(resp.boot_id.as_str());
        if reset && used_since > 0 {
            match fetch_logs(ip, 0).await {
                Ok(r) => resp = r,
                Err(e) => {
                    debug!(project = %project_id, ip, error = %e, "log refetch failed");
                    return;
                }
            }
        }

        if resp.lines.is_empty() {
            // Record the (possibly new) boot_id so future resets are detected even
            // when the agent currently has no buffered output.
            if reset {
                self.update_cursor(project_id, resp.boot_id, 0).await;
            }
            return;
        }

        let new_seq = resp
            .lines
            .iter()
            .map(|l| l.seq)
            .max()
            .unwrap_or(used_since);
        let boot_id = resp.boot_id.clone();

        if let Err(e) = self.log_store.append(project_id, &resp.lines) {
            warn!(project = %project_id, error = %e, "failed to persist shipped logs");
            return;
        }

        self.update_cursor(project_id, boot_id, new_seq).await;
    }

    async fn update_cursor(&self, project_id: &str, boot_id: String, seq: u64) {
        let snapshot = {
            let mut cursors = self.cursors.lock().await;
            cursors.insert(project_id.to_string(), Cursor { boot_id, seq });
            cursors.clone()
        };
        self.persist(&snapshot);
    }

    fn persist(&self, cursors: &HashMap<String, Cursor>) {
        let Ok(json) = serde_json::to_vec(cursors) else {
            return;
        };
        if let Err(e) = std::fs::write(&self.cursor_path, json) {
            debug!(error = %e, "failed to persist log cursors");
        }
    }
}

fn load_cursors(path: &Path) -> HashMap<String, Cursor> {
    std::fs::read(path)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .unwrap_or_default()
}

async fn fetch_logs(ip: &str, since: u64) -> Result<LogsResponse> {
    // Bound the whole connect->handshake->send->collect against a wedged agent so
    // neither the 2s steady-state poll nor the shutdown final-flush can hang (and
    // so the spawned `conn` task can't accumulate against an unresponsive guest).
    tokio::time::timeout(Duration::from_secs(3), async {
        let stream = tokio::net::TcpStream::connect(format!("{ip}:80")).await?;
        let io = hyper_util::rt::TokioIo::new(stream);
        let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
        tokio::spawn(conn);

        let url = format!("http://{ip}:80/_jkbase/logs?since={since}");
        let req = hyper::Request::builder()
            .uri(url)
            .body(http_body_util::Empty::<hyper::body::Bytes>::new())?;

        let resp = sender.send_request(req).await?;
        let body = http_body_util::BodyExt::collect(resp.into_body())
            .await?
            .to_bytes();
        Ok(serde_json::from_slice(&body)?)
    })
    .await
    .map_err(|_| anyhow::anyhow!("fetch_logs timed out"))?
}
