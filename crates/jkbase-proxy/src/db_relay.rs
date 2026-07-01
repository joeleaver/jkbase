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
    /// Set once the graceful-drain sweep ([`Self::cancel_all`]) has run. A relay that
    /// registers AFTER that one-shot sweep would otherwise never be signalled and would
    /// pin the drain barrier until the hard `DRAIN_GRACE` exit; so once draining, every
    /// new registration is cancelled at birth.
    draining: bool,
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
                draining: false,
            }),
        })
    }

    /// Atomically reserve a live-relay slot for `project_id` authorized by `akid`, enforcing
    /// `per_project_max` UNDER THE SAME LOCK as the insert. Returns `None` if the project is
    /// already at its cap. On success, returns the RAII [`RelayGuard`] (hold it for the
    /// relay's lifetime — drop decrements the gauge) and the [`CancellationToken`] the relay
    /// must force-close on.
    ///
    /// Folding the cap check into the insert is load-bearing: a check-then-register split
    /// (read `conn_count`, `.await` a wake, then register) is a TOCTOU that lets many
    /// concurrent connections for one project all observe `< max` and blow past the cap,
    /// monopolizing the shared global pool. Callers MUST register through this BEFORE any
    /// wake `.await`, so the relay is visible to `cancel_key`/`cancel_project` for the whole
    /// setup window (else revocation during setup misses it — [R5]).
    pub fn try_register(
        self: &Arc<Self>,
        project_id: &str,
        akid: &str,
        per_project_max: usize,
    ) -> Option<(RelayGuard, CancellationToken)> {
        let cancel = CancellationToken::new();
        let id = {
            let mut inner = self.inner.lock().unwrap();
            let count = inner
                .by_project
                .get(project_id)
                .map(|v| v.len())
                .unwrap_or(0);
            if count >= per_project_max {
                return None;
            }
            let id = inner.next_id;
            inner.next_id += 1;
            let draining = inner.draining;
            inner
                .by_project
                .entry(project_id.to_string())
                .or_default()
                .push(Entry {
                    id,
                    akid: akid.to_string(),
                    cancel: cancel.clone(),
                });
            // [R-drain] Registered into an already-draining registry ⇒ the one-shot
            // `cancel_all` sweep has passed; cancel at birth so this relay can't pin the
            // drain barrier past the hard exit.
            if draining {
                cancel.cancel();
            }
            id
        };
        Some((
            RelayGuard {
                registry: self.clone(),
                project_id: project_id.to_string(),
                id,
            },
            cancel,
        ))
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

    /// [R-drain] Cancel ALL live relays (graceful-drain deadline) and mark the registry
    /// draining so any relay that registers after this sweep is cancelled at birth (closing
    /// the shutdown-window race). Returns the count signalled in this sweep.
    pub fn cancel_all(&self) -> usize {
        let mut inner = self.inner.lock().unwrap();
        inner.draining = true;
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

    // A generous cap for tests that don't exercise the per-project limit.
    const MAX: usize = 64;

    #[test]
    fn register_counts_and_raii_deregisters() {
        let reg = DbRelayRegistry::new();
        assert_eq!(reg.conn_count("p"), 0);
        let (g1, _t1) = reg.try_register("p", "JKBDaaa", MAX).unwrap();
        let (g2, _t2) = reg.try_register("p", "JKBDbbb", MAX).unwrap();
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
    fn per_project_cap_is_enforced_atomically_in_register() {
        let reg = DbRelayRegistry::new();
        // Fill a project to its cap of 2.
        let (_g1, _t1) = reg.try_register("p", "k", 2).unwrap();
        let (g2, _t2) = reg.try_register("p", "k", 2).unwrap();
        // The 3rd is refused — the cap is checked under the same lock as the insert, so
        // concurrent registrations can't all slip past a stale count.
        assert!(reg.try_register("p", "k", 2).is_none());
        assert_eq!(reg.conn_count("p"), 2);
        // A different project has its own budget.
        assert!(reg.try_register("q", "k", 2).is_some());
        // Freeing a slot re-opens the project.
        drop(g2);
        assert!(reg.try_register("p", "k", 2).is_some());
    }

    #[test]
    fn cancel_key_signals_only_that_keys_relays() {
        let reg = DbRelayRegistry::new();
        let (_g1, t1) = reg.try_register("p", "JKBDaaa", MAX).unwrap();
        let (_g2, t2) = reg.try_register("p", "JKBDbbb", MAX).unwrap();
        let (_g3, t3) = reg.try_register("q", "JKBDaaa", MAX).unwrap();
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
        let (_gp, tp) = reg.try_register("p", "k", MAX).unwrap();
        let (_gq, tq) = reg.try_register("q", "k", MAX).unwrap();
        assert_eq!(reg.cancel_project("p"), 1);
        assert!(tp.is_cancelled());
        assert!(!tq.is_cancelled());
        // cancel_all gets the remainder.
        assert_eq!(reg.cancel_all(), 2); // both entries still registered (tasks not yet unwound)
        assert!(tq.is_cancelled());
    }

    #[test]
    fn registering_after_drain_is_cancelled_at_birth() {
        let reg = DbRelayRegistry::new();
        // Drain sweep runs (0 live relays), marking the registry draining.
        assert_eq!(reg.cancel_all(), 0);
        // A relay that registers in the shutdown window is cancelled immediately, so it
        // can't pin the drain barrier past the hard deadline.
        let (_g, t) = reg.try_register("p", "k", MAX).unwrap();
        assert!(t.is_cancelled());
    }
}
