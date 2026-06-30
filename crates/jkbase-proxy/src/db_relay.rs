//! Per-project registry of LIVE managed-DB reach-plane relays.
//!
//! A raw DB relay is long-lived and never EOFs on its own, so three otherwise-separate
//! concerns all need a handle to each live relay:
//! - **§5 liveness** — the idle-detection loop must exclude a project that has an open
//!   relay from hibernation (a realtime subscription can be open but byte-silent), which
//!   it reads here as `conn_count > 0`.
//! - **[R-drain]** — at the graceful-drain deadline the edge force-closes every relay
//!   (they won't drain naturally) via [`Self::cancel_all`].
//! - **[R5]** — revoking a DB key (or deleting/transferring a project) must drop LIVE
//!   relays NOW, not just block new connects — [`Self::cancel_key`]/[`Self::cancel_project`].
//!
//! Each relay registers on connect and gets a [`RelayGuard`] (RAII — deregisters on drop,
//! so the per-project gauge falls exactly when the relay task ends) plus a
//! [`CancellationToken`] it must select on (the relay seam's `RelayHooks::cancel`).
//! Cancellation only signals; the relay task's own guard does the removal as it unwinds.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

pub struct DbRelayRegistry {
    inner: Mutex<Inner>,
}

struct Inner {
    next_id: u64,
    by_project: HashMap<String, Vec<Entry>>,
}

struct Entry {
    id: u64,
    /// Which DB key authorized this relay — so a key revocation drops exactly its relays.
    akid: String,
    cancel: CancellationToken,
}

impl DbRelayRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                next_id: 0,
                by_project: HashMap::new(),
            }),
        })
    }

    /// Register a live relay for `project_id` authorized by `akid`. Returns the RAII
    /// [`RelayGuard`] (hold it for the relay's lifetime) and the [`CancellationToken`]
    /// the relay must force-close on.
    pub fn register(
        self: &Arc<Self>,
        project_id: &str,
        akid: &str,
    ) -> (RelayGuard, CancellationToken) {
        let cancel = CancellationToken::new();
        let id = {
            let mut inner = self.inner.lock().unwrap();
            let id = inner.next_id;
            inner.next_id += 1;
            inner
                .by_project
                .entry(project_id.to_string())
                .or_default()
                .push(Entry {
                    id,
                    akid: akid.to_string(),
                    cancel: cancel.clone(),
                });
            id
        };
        (
            RelayGuard {
                registry: self.clone(),
                project_id: project_id.to_string(),
                id,
            },
            cancel,
        )
    }

    /// Live relay count for `project_id`. The idle loop excludes a project with `> 0`
    /// from hibernation (§5).
    pub fn conn_count(&self, project_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .by_project
            .get(project_id)
            .map(|v| v.len())
            .unwrap_or(0)
    }

    /// Total live relays across all projects (metrics / a global ceiling).
    pub fn total(&self) -> usize {
        self.inner
            .lock()
            .unwrap()
            .by_project
            .values()
            .map(|v| v.len())
            .sum()
    }

    /// [R5] Cancel every live relay authorized by `akid` (key revocation). Returns how
    /// many were signalled; their RAII guards remove the entries as the tasks unwind.
    pub fn cancel_key(&self, akid: &str) -> usize {
        let inner = self.inner.lock().unwrap();
        let mut n = 0;
        for entries in inner.by_project.values() {
            for e in entries {
                if e.akid == akid {
                    e.cancel.cancel();
                    n += 1;
                }
            }
        }
        n
    }

    /// [R5] Cancel every live relay for `project_id` (project delete / owner transfer).
    pub fn cancel_project(&self, project_id: &str) -> usize {
        let inner = self.inner.lock().unwrap();
        match inner.by_project.get(project_id) {
            Some(entries) => {
                for e in entries {
                    e.cancel.cancel();
                }
                entries.len()
            }
            None => 0,
        }
    }

    /// [R-drain] Cancel ALL live relays (graceful-drain deadline). Returns the count.
    pub fn cancel_all(&self) -> usize {
        let inner = self.inner.lock().unwrap();
        let mut n = 0;
        for entries in inner.by_project.values() {
            for e in entries {
                e.cancel.cancel();
                n += 1;
            }
        }
        n
    }
}

/// RAII handle: deregisters its relay (decrementing the per-project gauge) on drop —
/// including when the relay task panics/unwinds.
pub struct RelayGuard {
    registry: Arc<DbRelayRegistry>,
    project_id: String,
    id: u64,
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock().unwrap();
        if let Some(entries) = inner.by_project.get_mut(&self.project_id) {
            entries.retain(|e| e.id != self.id);
            if entries.is_empty() {
                inner.by_project.remove(&self.project_id);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn register_counts_and_raii_deregisters() {
        let reg = DbRelayRegistry::new();
        assert_eq!(reg.conn_count("p"), 0);
        let (g1, _t1) = reg.register("p", "JKBDaaa");
        let (g2, _t2) = reg.register("p", "JKBDbbb");
        assert_eq!(reg.conn_count("p"), 2);
        assert_eq!(reg.total(), 2);
        drop(g1);
        assert_eq!(reg.conn_count("p"), 1);
        drop(g2);
        assert_eq!(reg.conn_count("p"), 0);
        // Empty project key is pruned.
        assert_eq!(reg.total(), 0);
    }

    #[test]
    fn cancel_key_signals_only_that_keys_relays() {
        let reg = DbRelayRegistry::new();
        let (_g1, t1) = reg.register("p", "JKBDaaa");
        let (_g2, t2) = reg.register("p", "JKBDbbb");
        let (_g3, t3) = reg.register("q", "JKBDaaa");
        assert!(!t1.is_cancelled() && !t2.is_cancelled() && !t3.is_cancelled());
        // Revoking key aaa cancels its relays across ALL projects, not key bbb's.
        assert_eq!(reg.cancel_key("JKBDaaa"), 2);
        assert!(t1.is_cancelled());
        assert!(t3.is_cancelled());
        assert!(!t2.is_cancelled());
    }

    #[test]
    fn cancel_project_and_all_are_scoped() {
        let reg = DbRelayRegistry::new();
        let (_gp, tp) = reg.register("p", "k");
        let (_gq, tq) = reg.register("q", "k");
        assert_eq!(reg.cancel_project("p"), 1);
        assert!(tp.is_cancelled());
        assert!(!tq.is_cancelled());
        // cancel_all gets the remainder.
        assert_eq!(reg.cancel_all(), 2); // both entries still registered (tasks not yet unwound)
        assert!(tq.is_cancelled());
    }
}
