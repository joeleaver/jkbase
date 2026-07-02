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

use std::collections::{HashMap, HashSet};
use std::sync::{Arc, Mutex};
use tokio_util::sync::CancellationToken;

pub struct DbRelayRegistry {
    inner: Mutex<Inner>,
}

struct Inner {
    next_id: u64,
    by_project: HashMap<String, Vec<Entry>>,
    /// Distinct project ids CURRENTLY held warm by ≥1 relay, grouped by owning
    /// tenant — the per-tenant warm-VM gauge. A project appears once regardless of
    /// how many relays it has (one project = one warm VM); ownerless projects
    /// (`tenant_id == None`) are not tracked here (only the per-project + global
    /// caps bound them). Used to enforce a per-tenant ceiling so one idle DB
    /// connection per project can't pin every VM warm.
    by_tenant: HashMap<String, HashSet<String>>,
    /// Total LIVE relays across all of a tenant's projects, grouped by owning tenant —
    /// the per-tenant relay-COUNT gauge. Distinct from `by_tenant`, which counts warm
    /// *projects* (VMs): a tenant with `warm_vm_max` projects each holding
    /// `per_project_max` relays would occupy `warm_vm_max * per_project_max` of the
    /// global pool, so the project cap alone lets one tenant monopolize it. This bounds
    /// a tenant's total relay footprint directly. Ownerless projects
    /// (`tenant_id == None`) are not tracked here.
    relays_by_tenant: HashMap<String, usize>,
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

/// Why [`DbRelayRegistry::try_register`] refused a relay — so the edge can map each
/// to the right refusal (both close the connection, but they are distinct signals).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayRejected {
    /// This project already has `per_project_max` live relays.
    PerProject,
    /// This tenant already holds `per_tenant_max` distinct projects warm via DB
    /// relays — a per-tenant warm-VM quota refusal.
    PerTenant,
    /// This tenant already holds `per_tenant_relay_max` total live relays across all
    /// its projects — a per-tenant relay-count fairness refusal, so one tenant can't
    /// fill the global pool via `warm_vm_max * per_project_max` relays.
    PerTenantRelays,
}

impl DbRelayRegistry {
    pub fn new() -> Arc<Self> {
        Arc::new(Self {
            inner: Mutex::new(Inner {
                next_id: 0,
                by_project: HashMap::new(),
                by_tenant: HashMap::new(),
                relays_by_tenant: HashMap::new(),
                draining: false,
            }),
        })
    }

    /// Atomically reserve a live-relay slot for `project_id` (owned by `tenant_id`)
    /// authorized by `akid`, enforcing THREE caps UNDER THE SAME LOCK as the insert:
    /// `per_project_max` (relays per project), `per_tenant_max` (distinct projects a
    /// tenant may hold warm), and `per_tenant_relay_max` (total relays a tenant may
    /// hold across all its projects). Returns `Err(RelayRejected::_)` at any cap. On
    /// success, returns the RAII [`RelayGuard`] (hold it for the relay's lifetime —
    /// drop decrements every gauge) and the [`CancellationToken`] the relay must
    /// force-close on.
    ///
    /// The per-tenant WARM-VM cap (`per_tenant_max`) only trips when this relay would
    /// make a NEW project warm (its first live relay); a second relay to an
    /// already-warm project doesn't add a VM, so it never counts against it. The
    /// per-tenant RELAY-COUNT cap (`per_tenant_relay_max`) trips on EVERY relay,
    /// warm-making or not — it bounds the tenant's slice of the global pool so
    /// `per_tenant_max * per_project_max` relays can't fill it and starve other
    /// tenants. `tenant_id == None` (ownerless project) skips both per-tenant
    /// dimensions entirely (only the per-project + global caps bound it).
    ///
    /// Folding the cap checks into the insert is load-bearing: a check-then-register
    /// split (read a count, `.await` a wake, then register) is a TOCTOU that lets many
    /// concurrent connections all observe `< max` and blow past the cap. Callers MUST
    /// register through this BEFORE any wake `.await`, so the relay is visible to
    /// `cancel_key`/`cancel_project` for the whole setup window (else revocation during
    /// setup misses it — [R5]).
    pub fn try_register(
        self: &Arc<Self>,
        project_id: &str,
        tenant_id: Option<&str>,
        akid: &str,
        per_project_max: usize,
        per_tenant_max: usize,
        per_tenant_relay_max: usize,
    ) -> Result<(RelayGuard, CancellationToken), RelayRejected> {
        let cancel = CancellationToken::new();
        let id = {
            let mut inner = self.inner.lock().unwrap();
            let count = inner
                .by_project
                .get(project_id)
                .map(|v| v.len())
                .unwrap_or(0);
            if count >= per_project_max {
                return Err(RelayRejected::PerProject);
            }
            // Per-tenant warm-VM cap — only when this is the project's FIRST relay
            // (count == 0), i.e. it's about to become warm. An owned project already
            // warm (count > 0) is already in `by_tenant` and adds no VM.
            let makes_project_warm = count == 0;
            if let Some(tid) = tenant_id
                && makes_project_warm
            {
                let warm = inner.by_tenant.get(tid).map(|s| s.len()).unwrap_or(0);
                if warm >= per_tenant_max {
                    return Err(RelayRejected::PerTenant);
                }
            }
            // Per-tenant relay-COUNT cap — bounds the tenant's total slice of the global
            // pool. Unlike the warm-VM cap this counts EVERY relay (warm-making or a 2nd
            // relay to an already-warm project), so `per_tenant_max * per_project_max`
            // relays can't fill the pool and starve other tenants.
            if let Some(tid) = tenant_id {
                let relays = inner.relays_by_tenant.get(tid).copied().unwrap_or(0);
                if relays >= per_tenant_relay_max {
                    return Err(RelayRejected::PerTenantRelays);
                }
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
            // Track the newly-warm project against its tenant (idempotent for a second
            // relay), and bump the tenant's total-relay gauge (every relay counts). We
            // only reach the insert when under all three caps.
            if let Some(tid) = tenant_id {
                inner
                    .by_tenant
                    .entry(tid.to_string())
                    .or_default()
                    .insert(project_id.to_string());
                *inner.relays_by_tenant.entry(tid.to_string()).or_insert(0) += 1;
            }
            // [R-drain] Registered into an already-draining registry ⇒ the one-shot
            // `cancel_all` sweep has passed; cancel at birth so this relay can't pin the
            // drain barrier past the hard exit.
            if draining {
                cancel.cancel();
            }
            id
        };
        Ok((
            RelayGuard {
                registry: self.clone(),
                project_id: project_id.to_string(),
                tenant_id: tenant_id.map(str::to_string),
                id,
            },
            cancel,
        ))
    }

    /// Count of distinct projects the tenant is CURRENTLY holding warm via DB
    /// relays (the per-tenant gauge). For metrics / inspection.
    pub fn warm_projects_for_tenant(&self, tenant_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .by_tenant
            .get(tenant_id)
            .map(|s| s.len())
            .unwrap_or(0)
    }

    /// Total live relays the tenant is CURRENTLY holding across all its projects (the
    /// per-tenant relay-count gauge). For metrics / inspection.
    pub fn relays_for_tenant(&self, tenant_id: &str) -> usize {
        self.inner
            .lock()
            .unwrap()
            .relays_by_tenant
            .get(tenant_id)
            .copied()
            .unwrap_or(0)
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

/// RAII handle: deregisters its relay (decrementing the per-project AND per-tenant
/// gauges) on drop — including when the relay task panics/unwinds.
pub struct RelayGuard {
    registry: Arc<DbRelayRegistry>,
    project_id: String,
    tenant_id: Option<String>,
    id: u64,
}

impl Drop for RelayGuard {
    fn drop(&mut self) {
        let mut inner = self.registry.inner.lock().unwrap();
        let mut project_went_cold = false;
        if let Some(entries) = inner.by_project.get_mut(&self.project_id) {
            entries.retain(|e| e.id != self.id);
            if entries.is_empty() {
                inner.by_project.remove(&self.project_id);
                project_went_cold = true;
            }
        }
        // Only when the project lost its LAST relay does it leave the tenant's warm
        // set (the VM may then hibernate); a still-live sibling relay keeps it warm.
        if project_went_cold
            && let Some(tid) = self.tenant_id.as_deref()
            && let Some(set) = inner.by_tenant.get_mut(tid)
        {
            set.remove(&self.project_id);
            if set.is_empty() {
                inner.by_tenant.remove(tid);
            }
        }
        // Every relay counts toward the tenant's total-relay gauge (independent of
        // whether the project went cold), so decrement on every drop, pruning at zero.
        if let Some(tid) = self.tenant_id.as_deref()
            && let Some(n) = inner.relays_by_tenant.get_mut(tid)
        {
            *n -= 1;
            if *n == 0 {
                inner.relays_by_tenant.remove(tid);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Generous caps for tests that don't exercise a specific limit.
    const MAX: usize = 64;
    const TMAX: usize = 64;
    const RMAX: usize = 64;

    #[test]
    fn register_counts_and_raii_deregisters() {
        let reg = DbRelayRegistry::new();
        assert_eq!(reg.conn_count("p"), 0);
        let (g1, _t1) = reg.try_register("p", Some("t"), "JKBDaaa", MAX, TMAX, RMAX).unwrap();
        let (g2, _t2) = reg.try_register("p", Some("t"), "JKBDbbb", MAX, TMAX, RMAX).unwrap();
        assert_eq!(reg.conn_count("p"), 2);
        assert_eq!(reg.total(), 2);
        // One warm project for the tenant despite two relays.
        assert_eq!(reg.warm_projects_for_tenant("t"), 1);
        drop(g1);
        assert_eq!(reg.conn_count("p"), 1);
        assert_eq!(reg.warm_projects_for_tenant("t"), 1);
        drop(g2);
        assert_eq!(reg.conn_count("p"), 0);
        // Empty project key is pruned, and the tenant frees its warm slot.
        assert_eq!(reg.total(), 0);
        assert_eq!(reg.warm_projects_for_tenant("t"), 0);
    }

    #[test]
    fn per_project_cap_is_enforced_atomically_in_register() {
        let reg = DbRelayRegistry::new();
        // Fill a project to its cap of 2.
        let (_g1, _t1) = reg.try_register("p", Some("t"), "k", 2, TMAX, RMAX).unwrap();
        let (g2, _t2) = reg.try_register("p", Some("t"), "k", 2, TMAX, RMAX).unwrap();
        // The 3rd is refused — the cap is checked under the same lock as the insert, so
        // concurrent registrations can't all slip past a stale count.
        assert!(matches!(
            reg.try_register("p", Some("t"), "k", 2, TMAX, RMAX),
            Err(RelayRejected::PerProject)
        ));
        assert_eq!(reg.conn_count("p"), 2);
        // A different project has its own budget.
        assert!(reg.try_register("q", Some("t"), "k", 2, TMAX, RMAX).is_ok());
        // Freeing a slot re-opens the project.
        drop(g2);
        assert!(reg.try_register("p", Some("t"), "k", 2, TMAX, RMAX).is_ok());
    }

    #[test]
    fn per_tenant_warm_vm_cap_is_enforced() {
        let reg = DbRelayRegistry::new();
        // Tenant `t` may hold at most 2 projects warm.
        let (_g1, _) = reg.try_register("p1", Some("t"), "k", MAX, 2, RMAX).unwrap();
        let (g2, _) = reg.try_register("p2", Some("t"), "k", MAX, 2, RMAX).unwrap();
        assert_eq!(reg.warm_projects_for_tenant("t"), 2);
        // A 3rd DISTINCT project for the same tenant is refused (PerTenant).
        assert!(matches!(
            reg.try_register("p3", Some("t"), "k", MAX, 2, RMAX),
            Err(RelayRejected::PerTenant)
        ));
        // A SECOND relay to an ALREADY-warm project adds no VM -> allowed (only the
        // per-project cap applies), and doesn't grow the tenant's warm set.
        assert!(reg.try_register("p1", Some("t"), "k", MAX, 2, RMAX).is_ok());
        assert_eq!(reg.warm_projects_for_tenant("t"), 2);
        // A different tenant has its own budget.
        assert!(reg.try_register("p3", Some("u"), "k", MAX, 2, RMAX).is_ok());
        // Ownerless projects skip the per-tenant cap entirely.
        assert!(reg.try_register("o1", None, "k", MAX, 2, RMAX).is_ok());
        assert!(reg.try_register("o2", None, "k", MAX, 2, RMAX).is_ok());
        // When p2 loses its last relay, the tenant frees a warm slot -> the 3rd fits.
        drop(g2);
        assert_eq!(reg.warm_projects_for_tenant("t"), 1);
        assert!(reg.try_register("p3", Some("t"), "k", MAX, 2, RMAX).is_ok());
    }

    #[test]
    fn per_tenant_relay_count_cap_is_enforced() {
        let reg = DbRelayRegistry::new();
        // Tenant `t` may hold at most 3 TOTAL relays across any mix of projects. Use
        // generous per-project + warm-VM caps so only the relay-count cap can trip.
        let (g1, _) = reg.try_register("p1", Some("t"), "k", MAX, MAX, 3).unwrap();
        // A 2nd relay to the SAME (already-warm) project still counts — unlike the
        // warm-VM cap, every relay is charged against the tenant's relay budget.
        let (_g2, _) = reg.try_register("p1", Some("t"), "k", MAX, MAX, 3).unwrap();
        let (_g3, _) = reg.try_register("p2", Some("t"), "k", MAX, MAX, 3).unwrap();
        assert_eq!(reg.relays_for_tenant("t"), 3);
        assert_eq!(reg.warm_projects_for_tenant("t"), 2);
        // The 4th relay is refused regardless of which project it targets.
        assert!(matches!(
            reg.try_register("p1", Some("t"), "k", MAX, MAX, 3),
            Err(RelayRejected::PerTenantRelays)
        ));
        assert!(matches!(
            reg.try_register("p3", Some("t"), "k", MAX, MAX, 3),
            Err(RelayRejected::PerTenantRelays)
        ));
        // A different tenant has its own relay budget.
        assert!(reg.try_register("q", Some("u"), "k", MAX, MAX, 3).is_ok());
        // Ownerless projects skip the per-tenant relay cap entirely.
        for _ in 0..5 {
            assert!(reg.try_register("o", None, "k", MAX, MAX, 3).is_ok());
        }
        // Dropping a relay frees exactly one slot for the tenant, even though its
        // project stays warm via the sibling relay.
        drop(g1);
        assert_eq!(reg.relays_for_tenant("t"), 2);
        assert_eq!(reg.warm_projects_for_tenant("t"), 2);
        // A fresh relay now fits under the freed budget — bind it so it stays live.
        let (_g4, _) = reg.try_register("p3", Some("t"), "k", MAX, MAX, 3).unwrap();
        assert_eq!(reg.relays_for_tenant("t"), 3);
    }

    #[test]
    fn cancel_key_signals_only_that_keys_relays() {
        let reg = DbRelayRegistry::new();
        let (_g1, t1) = reg.try_register("p", Some("t"), "JKBDaaa", MAX, TMAX, RMAX).unwrap();
        let (_g2, t2) = reg.try_register("p", Some("t"), "JKBDbbb", MAX, TMAX, RMAX).unwrap();
        let (_g3, t3) = reg.try_register("q", Some("t"), "JKBDaaa", MAX, TMAX, RMAX).unwrap();
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
        let (_gp, tp) = reg.try_register("p", Some("t"), "k", MAX, TMAX, RMAX).unwrap();
        let (_gq, tq) = reg.try_register("q", Some("t"), "k", MAX, TMAX, RMAX).unwrap();
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
        let (_g, t) = reg.try_register("p", Some("t"), "k", MAX, TMAX, RMAX).unwrap();
        assert!(t.is_cancelled());
    }
}
