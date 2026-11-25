//! The host-wide build-memory budget every build VM, of every tenant, reserves from before it
//! boots (see `build_sizing` for why it exists: per-project VM sizes are only safe on a shared
//! host if their sum is bounded).
//!
//! The budget is itself a cross-tenant resource, and accounts are free, so its admission policy
//! is the isolation boundary: **max-min fair across tenants, with a pinned head.**
//! - Each tenant's waiters queue FIFO. When memory frees, the tenant holding the LEAST right
//!   now goes next; among equals, the tenant served longest ago (round-robin), then the one
//!   whose front waiter arrived first. A tenant with nothing running is therefore never queued
//!   behind another tenant's backlog, however many targets or projects that tenant floods in —
//!   not even behind one whose VM just exited. A fixed per-tenant share can't give that: two
//!   (free) accounts at half each still own the whole host.
//! - Once memory frees but not enough for the fairest waiter, it is PINNED as the head: nothing
//!   else is admitted until it fits or gives up, even a smaller request that would fit, or a
//!   tenant that turns fairer meanwhile (re-choosing the head on every release would let tenants cycling small
//!   builds starve a big — admin-granted — VM forever). So the head waits at most until the VMs
//!   already running exit: one build-VM lifetime. `max_wait` (twice that) therefore only
//!   expires for a waiter queued behind OTHER waiters, e.g. its own tenant's backlog, and the
//!   error says which.
//! - Work-conserving: with no contention, one tenant may use the whole budget.
//!
//! Work under the lock is O(tenants waiting) per admission (plus a leaving waiter's own tenant
//! queue), never O(all waiters): a tenant queueing many targets only lengthens its own queue.
//!
//! Residual (not this module's to fix): a tenant with many accounts gets one fair slot per
//! account. Per-tenant fairness is the strongest policy available without a non-free identity.

use std::collections::{HashMap, VecDeque};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use anyhow::{Result, bail};
use tokio::sync::oneshot;

/// Host-wide build-memory budget (MiB). Cheap to share behind an `Arc`.
#[derive(Debug)]
pub struct BuildMemBudget {
    inner: Arc<Inner>,
}

#[derive(Debug)]
struct Inner {
    total_mib: u32,
    max_wait: Duration,
    state: Mutex<State>,
}

#[derive(Debug, Default)]
struct State {
    free_mib: u32,
    /// MiB currently held, per tenant. A tenant holding nothing has no entry.
    held: HashMap<String, u32>,
    /// Each waiting tenant's FIFO queue. A tenant with no waiters has no entry.
    queues: HashMap<String, VecDeque<Waiter>>,
    /// The tenant whose FRONT waiter is the pinned head: chosen as fairest when memory freed, but
    /// too big for what was free. Only it may be admitted until it fits or leaves.
    pinned: Option<String>,
    next_id: u64,
    /// When each tenant with holdings or waiters was last admitted (`grant_seq` order): the
    /// round-robin tie-break. Idle tenants are forgotten (they come back first, as they should).
    last_grant: HashMap<String, u64>,
    grant_seq: u64,
}

#[derive(Debug)]
struct Waiter {
    id: u64,
    mib: u32,
    grant: oneshot::Sender<MemReservation>,
}

/// One build VM's hold on the budget; dropping it returns the memory and admits whoever is next.
#[derive(Debug)]
pub struct MemReservation {
    budget: Arc<Inner>,
    tenant: String,
    mib: u32,
}

impl Drop for MemReservation {
    fn drop(&mut self) {
        let undelivered = {
            let mut st = self.budget.lock();
            st.free_mib += self.mib;
            if let Some(h) = st.held.get_mut(&self.tenant) {
                *h -= self.mib;
                if *h == 0 {
                    st.held.remove(&self.tenant);
                }
            }
            dispatch(&self.budget, &mut st)
        };
        // Grants whose waiter is already gone release here, OUTSIDE the lock (their own drop
        // re-locks and dispatches again).
        drop(undelivered);
    }
}

impl Inner {
    fn lock(&self) -> MutexGuard<'_, State> {
        // The state is only ever mutated by complete, panic-free critical sections.
        self.state.lock().unwrap_or_else(|p| p.into_inner())
    }
}

/// The tenant to serve next: the pinned one if any, else the one holding least, then served
/// longest ago, then whose front waiter arrived first. O(tenants waiting).
fn next_tenant(st: &State) -> Option<String> {
    if let Some(t) = &st.pinned {
        return Some(t.clone());
    }
    st.queues
        .iter()
        .filter_map(|(t, q)| q.front().map(|w| (t, w.id)))
        .min_by_key(|(t, front_id)| {
            let held = st.held.get(*t).copied().unwrap_or(0);
            let last = st.last_grant.get(*t).copied().unwrap_or(0);
            (held, last, *front_id)
        })
        .map(|(t, _)| t.clone())
}

/// Admit waiters while the next one fits; pin it as the head when it doesn't. Returns the
/// reservations whose waiter had already dropped its receiver, for the caller to drop after
/// unlocking.
fn dispatch(budget: &Arc<Inner>, st: &mut State) -> Vec<MemReservation> {
    let mut undelivered = Vec::new();
    while let Some(tenant) = next_tenant(st) {
        let queue = st.queues.get_mut(&tenant).expect("next_tenant has a queue");
        let mib = queue.front().expect("queues are never left empty").mib;
        if mib > st.free_mib {
            // Memory is now accumulating for this waiter: pin it, so nobody takes that memory
            // past it until it fits or leaves. With NOTHING free there is nothing to protect, and
            // pinning would keep a tenant arriving fairer (nothing running) behind it.
            if st.free_mib > 0 {
                st.pinned = Some(tenant);
            }
            break;
        }
        let w = queue.pop_front().expect("checked above");
        if queue.is_empty() {
            st.queues.remove(&tenant);
        }
        st.pinned = None;
        st.free_mib -= mib;
        *st.held.entry(tenant.clone()).or_default() += mib;
        st.grant_seq += 1;
        let seq = st.grant_seq;
        st.last_grant.insert(tenant.clone(), seq);
        let r = MemReservation {
            budget: budget.clone(),
            tenant,
            mib,
        };
        if let Err(r) = w.grant.send(r) {
            undelivered.push(r);
        }
    }
    let State {
        held,
        queues,
        last_grant,
        ..
    } = st;
    last_grant.retain(|t, _| held.contains_key(t) || queues.contains_key(t));
    undelivered
}

/// Removes a cancelled (dropped) or timed-out reservation attempt from the queue, so a waiter
/// that gave up never blocks the head.
struct QueueSlot<'a> {
    budget: &'a Arc<Inner>,
    tenant: String,
    id: u64,
}

impl QueueSlot<'_> {
    /// Leave the queue. True if this waiter was still queued (not yet granted).
    fn leave(&self) -> bool {
        let undelivered;
        let was_queued = {
            let mut st = self.budget.lock();
            let Some(queue) = st.queues.get_mut(&self.tenant) else {
                return false;
            };
            let Some(pos) = queue.iter().position(|w| w.id == self.id) else {
                return false;
            };
            queue.remove(pos);
            if queue.is_empty() {
                st.queues.remove(&self.tenant);
            }
            // The pinned head is its tenant's FRONT waiter; if that was us, unpin.
            if pos == 0 && st.pinned.as_deref() == Some(self.tenant.as_str()) {
                st.pinned = None;
            }
            // Removing the head may let the next waiter in.
            undelivered = dispatch(self.budget, &mut st);
            true
        };
        drop(undelivered);
        was_queued
    }
}

impl Drop for QueueSlot<'_> {
    fn drop(&mut self) {
        self.leave();
    }
}

impl BuildMemBudget {
    pub fn new(total_mib: u32, max_wait: Duration) -> Self {
        Self {
            inner: Arc::new(Inner {
                total_mib,
                max_wait,
                state: Mutex::new(State {
                    free_mib: total_mib,
                    ..State::default()
                }),
            }),
        }
    }

    /// A budget no test build can exhaust (1 TiB, waits up to an hour), for harnesses that
    /// exercise everything but the budget itself.
    #[cfg(test)]
    pub fn unlimited() -> Self {
        Self::new(1 << 20, Duration::from_secs(3600))
    }

    pub fn total_mib(&self) -> u32 {
        self.inner.total_mib
    }

    /// Reserve `mib` for one build VM of `tenant`, waiting (up to `max_wait`) for its fair turn.
    /// A VM larger than the whole budget could never fit, so it's refused at once.
    pub async fn reserve(&self, tenant: &str, mib: u32) -> Result<MemReservation> {
        let total = self.inner.total_mib;
        if mib > total {
            bail!(
                "build VM needs {mib} MiB but the host's whole build-memory budget is {total} MiB; \
                 the platform operator must lower this project's build memory"
            );
        }
        let (tx, mut rx) = oneshot::channel();
        let (slot, undelivered) = {
            let mut st = self.inner.lock();
            let id = st.next_id;
            st.next_id += 1;
            st.queues
                .entry(tenant.to_string())
                .or_default()
                .push_back(Waiter { id, mib, grant: tx });
            let slot = QueueSlot {
                budget: &self.inner,
                tenant: tenant.to_string(),
                id,
            };
            (slot, dispatch(&self.inner, &mut st))
        };
        drop(undelivered);
        // Cancel-safe: if this future is dropped mid-wait, `slot` leaves the queue, and a grant
        // already sitting in the channel is dropped with `rx`, returning its memory.
        let wait = self.inner.max_wait;
        match tokio::time::timeout(wait, &mut rx).await {
            Ok(Ok(r)) => Ok(r),
            Ok(Err(_)) => unreachable!("the sender lives in the queue until it is sent"),
            Err(_) => {
                if !slot.leave() {
                    // Granted between the deadline and leaving the queue: take it.
                    if let Ok(r) = rx.try_recv() {
                        return Ok(r);
                    }
                }
                let own = self.inner.lock().held.get(tenant).copied().unwrap_or(0);
                let secs = wait.as_secs();
                if own > 0 {
                    bail!(
                        "this build VM ({mib} MiB) waited {secs}s for build memory behind this \
                         account's other running builds ({own} MiB); deploy fewer projects at \
                         once, or retry"
                    )
                }
                bail!(
                    "the host's build capacity stayed busy for {secs}s (this build VM needs \
                     {mib} MiB); retry the deploy"
                )
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SHORT: Duration = Duration::from_millis(50);

    async fn not_admitted(b: &BuildMemBudget, tenant: &str, mib: u32) -> bool {
        tokio::time::timeout(SHORT, b.reserve(tenant, mib))
            .await
            .is_err()
    }

    fn queued(b: &BuildMemBudget) -> usize {
        b.inner.lock().queues.values().map(VecDeque::len).sum()
    }

    #[tokio::test]
    async fn admits_what_fits_and_refuses_what_never_can() {
        let b = BuildMemBudget::new(8192, Duration::from_secs(5));
        let a = b.reserve("t1", 4096).await.unwrap();
        let c = b.reserve("t2", 4096).await.unwrap();
        assert!(not_admitted(&b, "t3", 1024).await, "budget exhausted");
        assert_eq!(queued(&b), 0, "a cancelled wait leaves the queue");
        drop(a);
        let d = b
            .reserve("t3", 4096)
            .await
            .expect("released memory is reusable");
        drop((c, d));
        {
            let st = b.inner.lock();
            assert_eq!((st.free_mib, st.held.len()), (8192, 0), "all returned");
        }
        let err = b.reserve("t1", 8193).await.unwrap_err().to_string();
        assert!(
            err.contains("8193 MiB") && err.contains("8192 MiB"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn one_tenant_may_use_an_idle_host_whole() {
        let b = BuildMemBudget::new(8192, Duration::from_secs(5));
        let _x = b.reserve("solo", 4096).await.unwrap();
        let _y = b.reserve("solo", 4096).await.unwrap();
    }

    // The cross-tenant DoS the review found: tenants flooding the budget (any number of
    // targets, from two free accounts) must not keep a tenant with nothing running waiting
    // behind their backlog — it gets the very next freed memory, even though the releasing
    // tenant then holds nothing too (round-robin: it was served more recently).
    #[tokio::test]
    async fn a_tenant_with_nothing_running_goes_before_others_backlogs() {
        let b = Arc::new(BuildMemBudget::new(8192, Duration::from_secs(5)));
        let a1 = b.reserve("greedy-a", 4096).await.unwrap();
        let _b1 = b.reserve("greedy-b", 4096).await.unwrap();
        let mut backlog = Vec::new();
        for t in ["greedy-a", "greedy-b", "greedy-a", "greedy-b"] {
            let b = b.clone();
            backlog.push(tokio::spawn(async move { b.reserve(t, 4096).await }));
        }
        while queued(&b) < 4 {
            tokio::task::yield_now().await;
        }
        let victim = {
            let b = b.clone();
            tokio::spawn(async move { b.reserve("victim", 4096).await })
        };
        while queued(&b) < 5 {
            tokio::task::yield_now().await;
        }
        drop(a1);
        let v = tokio::time::timeout(Duration::from_secs(1), victim)
            .await
            .expect("the victim is admitted on the first release")
            .unwrap()
            .unwrap();
        assert_eq!(queued(&b), 4, "no greedy waiter went first");
        drop(v);
        for h in backlog {
            h.abort();
        }
    }

    #[tokio::test]
    async fn the_head_is_never_overtaken_so_big_vms_are_not_starved() {
        let b = Arc::new(BuildMemBudget::new(8192, Duration::from_secs(5)));
        let held = b.reserve("busy", 4096).await.unwrap();
        // `big` (holding nothing) is the fairest waiter but doesn't fit yet...
        let big = {
            let b = b.clone();
            tokio::spawn(async move { b.reserve("big", 6144).await })
        };
        while queued(&b) < 1 {
            tokio::task::yield_now().await;
        }
        // ...so a later small request that WOULD fit waits behind it.
        assert!(not_admitted(&b, "small", 1024).await);
        drop(held);
        let r = tokio::time::timeout(Duration::from_secs(1), big)
            .await
            .expect("the head is admitted once enough frees")
            .unwrap()
            .unwrap();
        drop(r);
    }

    // Review round 3: with the head re-chosen on every release, tenants cycling small builds
    // (each coming back idle, so "fairer" than the waiting big VM) overtook it forever.
    #[tokio::test]
    async fn a_pinned_head_is_not_overtaken_by_tenants_cycling_small_builds() {
        let b = Arc::new(BuildMemBudget::new(8192, Duration::from_secs(5)));
        let a = b.reserve("cycler-a", 4096).await.unwrap();
        let c = b.reserve("cycler-b", 4096).await.unwrap();
        let big = {
            let b = b.clone();
            tokio::spawn(async move { b.reserve("big", 8192).await })
        };
        while queued(&b) < 1 {
            tokio::task::yield_now().await;
        }
        // A's build exits; `big` still doesn't fit (B holds 4096), so it is pinned...
        drop(a);
        // ...and A, back idle and holding nothing, can't take the freed memory past it.
        assert!(not_admitted(&b, "cycler-a", 4096).await);
        drop(c);
        let r = tokio::time::timeout(Duration::from_secs(1), big)
            .await
            .expect("the pinned head is admitted once the running VMs exit")
            .unwrap()
            .unwrap();
        assert_eq!(queued(&b), 0);
        drop(r);
        b.reserve("cycler-a", 4096).await.expect("budget intact");
    }

    #[tokio::test]
    async fn waiting_is_bounded_and_says_whose_builds_were_in_the_way() {
        let b = BuildMemBudget::new(4096, SHORT);
        let held = b.reserve("t1", 4096).await.unwrap();
        let err = b.reserve("t2", 4096).await.unwrap_err().to_string();
        assert!(err.contains("host's build capacity stayed busy"), "{err}");
        let err = b.reserve("t1", 4096).await.unwrap_err().to_string();
        assert!(
            err.contains("this account's other running builds (4096 MiB)"),
            "{err}"
        );
        assert_eq!(queued(&b), 0, "timed-out waiters leave the queue");
        drop(held);
        b.reserve("t2", 4096)
            .await
            .expect("budget intact after timeouts");
    }

    #[tokio::test]
    async fn a_cancelled_head_unblocks_the_next_waiter() {
        let b = Arc::new(BuildMemBudget::new(8192, Duration::from_secs(5)));
        let held = b.reserve("busy", 4096).await.unwrap();
        let big = {
            let b = b.clone();
            tokio::spawn(async move { b.reserve("big", 8192).await })
        };
        while queued(&b) < 1 {
            tokio::task::yield_now().await;
        }
        let small = {
            let b = b.clone();
            tokio::spawn(async move { b.reserve("small", 4096).await })
        };
        while queued(&b) < 2 {
            tokio::task::yield_now().await;
        }
        big.abort();
        let _ = big.await;
        let s = tokio::time::timeout(Duration::from_secs(1), small)
            .await
            .expect("the head left, so the next one fits")
            .unwrap()
            .unwrap();
        drop((held, s));
    }
}
