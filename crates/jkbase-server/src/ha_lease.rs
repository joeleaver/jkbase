//! HA lease plane: the single-leader election over the `cluster-leader` lease and the data-disk
//! write-boundary self-fence that renews every held disk lease and stops this host's VM for any
//! project whose lease it loses, before a survivor can attach.

use crate::{PlatformState, VmLifecycle, handoff};
use anyhow::Result;
use jkbase_substrate::{FenceToken, Lease, SubstrateError};
use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use tracing::{info, warn};

// HA P2 — cluster leader election parameters.
pub(crate) const LEADER_SCOPE: &str = "cluster-leader";

pub(crate) const LEADER_TTL: Duration = Duration::from_secs(20);

pub(crate) const LEADER_TICK: Duration = Duration::from_secs(5);

/// Step down once leadership's time-since-last-successful-renew reaches this (a real
/// supersession steps down immediately). Keeps
/// `LEADER_FENCE_DEADLINE + (LEADER_TICK + RENEW_RPC_TIMEOUT) < LEADER_TTL` so a deposed
/// leader yields before a peer could steal its still-live key.
pub(crate) const LEADER_FENCE_DEADLINE: Duration = Duration::from_secs(8);

/// Outcome of evaluating one lease renewal in the fence/election loops. We must
/// discriminate a genuine loss from a transient backend blip: the substrate returns
/// [`SubstrateError::Fenced`] only when a newer token has superseded us (etcd maps an
/// expired/absent key here too) — a definitive loss — and a catch-all
/// [`SubstrateError::Backend`] / I/O error when the authority was momentarily
/// unreachable while we STILL hold the lease. Acting destructively on the latter (kill
/// a live VM / drop leadership) on one dropped packet is a self-inflicted outage, so
/// transient errors are tolerated until a deadline measured from the LAST SUCCESSFUL
/// renew (the same clock the lease TTL runs on, kept below it) before failing closed.
#[derive(Debug, PartialEq, Eq)]
pub(crate) enum FenceDecision {
    /// Renewal confirmed — we hold the lease; reset the last-success clock.
    Hold,
    /// Transient failure, last success still within the deadline — keep the lease, retry.
    KeepWaiting,
    /// Definitively lost (superseded/expired), or last success aged past the deadline —
    /// act now (self-fence / step down), failing closed before the lease can expire.
    FenceNow,
}

/// Decide what a renewal result means. `last_success` is when this scope's lease was last
/// confirmed; `now`/`deadline` bound how long transient failures are tolerated. Anchoring
/// at last success (not first-observed-failure) and bounding each renew RPC keeps the
/// self-fence ahead of the lease TTL even when renews hang or fail slowly under a partition.
pub(crate) fn evaluate_renew(
    result: &Result<FenceToken, SubstrateError>,
    last_success: Instant,
    now: Instant,
    deadline: Duration,
) -> FenceDecision {
    match result {
        Ok(_) => FenceDecision::Hold,
        // A newer token superseded us (etcd also maps an expired/absent key here): lost.
        Err(SubstrateError::Fenced { .. }) => FenceDecision::FenceNow,
        // Transient (backend unreachable / I/O / a timed-out renew RPC): we still hold the
        // lease. Tolerate until we've been unable to confirm it for `deadline` since the
        // last success — then fail closed before the TTL can expire and admit a survivor.
        Err(_) => {
            if now.duration_since(last_success) >= deadline {
                FenceDecision::FenceNow
            } else {
                FenceDecision::KeepWaiting
            }
        }
    }
}

/// HA P2 — cluster leader election. The elected leader (holder of the `cluster-leader`
/// lease) will own cluster-wide placement (P3); followers reconcile only their own host.
/// On a single node the one process wins the lease and stays leader. Backend-agnostic:
/// acquire once, then renew each tick — a no-op re-assert for `FlockLease`, the TTL
/// keepalive for a distributed lease — and on a lost/expired token drop back to
/// contender and re-acquire. `is_leader` is advisory at P2 (nothing gates on it yet);
/// the data-disk write-boundary self-fence, NOT this flag, is the split-brain guarantee.
pub(crate) async fn leader_election_loop(
    lease: Arc<dyn Lease>,
    host_id: String,
    is_leader: Arc<AtomicBool>,
) {
    let mut token: Option<FenceToken> = None;
    let mut last_success = Instant::now();
    loop {
        if let Some(t) = token.take() {
            // Re-assert leadership (keepalive), bounded so a blackhole partition can't hang
            // the loop. Discriminate a genuine loss (Fenced → step down now) from a transient
            // blip/timeout (retain within the deadline) so one dropped packet never flaps.
            let result =
                match tokio::time::timeout(RENEW_RPC_TIMEOUT, lease.renew(&t, LEADER_TTL)).await {
                    Ok(r) => r,
                    Err(_) => Err(SubstrateError::Backend(
                        "leader lease renew timed out".into(),
                    )),
                };
            match evaluate_renew(&result, last_success, Instant::now(), LEADER_FENCE_DEADLINE) {
                FenceDecision::Hold => {
                    last_success = Instant::now();
                    is_leader.store(true, Ordering::Relaxed);
                    token = Some(result.unwrap_or(t)); // adopt the refreshed token
                }
                FenceDecision::KeepWaiting => {
                    // Still leader — the lease is held; the authority is briefly unreachable.
                    // Keep the token and retry next tick.
                    is_leader.store(true, Ordering::Relaxed);
                    token = Some(t);
                    if let Err(e) = &result {
                        warn!(host_id = %host_id, error = %e,
                              "cluster-leader renew failed transiently; retaining leadership within deadline");
                    }
                }
                FenceDecision::FenceNow => {
                    is_leader.store(false, Ordering::Relaxed);
                    token = None;
                    warn!(host_id = %host_id, "lost cluster leadership; re-contesting");
                }
            }
        } else {
            // We are a contender: try to win the lease.
            match lease.acquire(LEADER_SCOPE, &host_id, LEADER_TTL).await {
                Ok(t) => {
                    info!(host_id = %host_id, epoch = t.epoch, "acquired cluster leadership");
                    is_leader.store(true, Ordering::Relaxed);
                    last_success = Instant::now();
                    token = Some(t);
                }
                // Another live host holds it — stay a follower and retry next tick.
                Err(SubstrateError::LeaseHeld { .. }) => is_leader.store(false, Ordering::Relaxed),
                Err(e) => {
                    is_leader.store(false, Ordering::Relaxed);
                    warn!(host_id = %host_id, error = %e, "cluster leader election error");
                }
            }
        }
        tokio::time::sleep(LEADER_TICK).await;
    }
}

/// HA P2 — the data-disk write-boundary self-fence: the split-brain safety core.
///
/// Periodically re-asserts (renews) every data-disk lease this host holds. A renewal
/// failure means the lease was lost — superseded by a survivor the leader reassigned
/// this project to, or expired under a network partition. The host then **self-fences**:
/// it kills its Firecracker process (stopping all writes) BEFORE the survivor attaches,
/// then detaches the disk. Combined with the restore-path fence (the survivor's
/// `attach_rwo` fails closed while a prior writer is provably alive), this guarantees a
/// data disk is never written by two hosts at once.
///
/// Inert on a single node: the node-local FlockLease renew always succeeds while this
/// process holds the lock, so the fence never trips. Cross-host correctness rides a
/// distributed lease (EtcdLease) and is exercised by the split-brain test harness.
pub(crate) async fn disk_fence_loop(platform: Arc<Mutex<PlatformState>>, lease: Arc<dyn Lease>) {
    // Per-project time of last SUCCESSFUL renew — the clock the etcd lease TTL also runs
    // on. A disk self-fences once its last success ages past DISK_FENCE_DEADLINE; a genuine
    // supersession (Fenced) self-fences immediately.
    let mut last_success: HashMap<String, Instant> = HashMap::new();
    loop {
        tokio::time::sleep(DISK_RENEW_INTERVAL).await;
        // Snapshot the held tokens, then renew OFF the platform lock — a slow or
        // unreachable lease backend must never block the whole platform.
        let held: Vec<(String, FenceToken)> = {
            let plat = platform.lock().await;
            plat.disk_tokens
                .iter()
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect()
        };
        let still_held: HashSet<String> = held.iter().map(|(p, _)| p.clone()).collect();
        // Seed last-success for freshly-acquired disks (just fenced + attached).
        for (project, _) in &held {
            last_success
                .entry(project.clone())
                .or_insert_with(Instant::now);
        }
        // Renew every held disk CONCURRENTLY, each bounded by RENEW_RPC_TIMEOUT, so one
        // slow/hung disk never delays another's self-fence (the serialization the review
        // flagged) — and a blackhole partition becomes a prompt transient error.
        let mut set = tokio::task::JoinSet::new();
        for (project, token) in held {
            let lease = lease.clone();
            set.spawn(async move {
                let r = match tokio::time::timeout(
                    RENEW_RPC_TIMEOUT,
                    lease.renew(&token, DISK_LEASE_TTL),
                )
                .await
                {
                    Ok(r) => r,
                    Err(_) => Err(SubstrateError::Backend("disk lease renew timed out".into())),
                };
                (project, token, r)
            });
        }
        while let Some(joined) = set.join_next().await {
            let (project, token, result) = match joined {
                Ok(tuple) => tuple,
                Err(_) => continue, // a renew task panicked; next tick retries
            };
            let since = last_success
                .get(&project)
                .copied()
                .unwrap_or_else(Instant::now);
            match evaluate_renew(&result, since, Instant::now(), DISK_FENCE_DEADLINE) {
                FenceDecision::Hold => {
                    last_success.insert(project, Instant::now());
                }
                FenceDecision::KeepWaiting => {
                    if let Err(e) = &result {
                        warn!(project = %project, scope = %token.scope, error = %e,
                              "data-disk lease renew failed transiently; retrying within deadline");
                    }
                }
                FenceDecision::FenceNow => {
                    last_success.remove(&project);
                    warn!(project = %project, scope = %token.scope,
                          "data-disk lease lost — self-fencing");
                    self_fence_project(&platform, &project, &token).await;
                }
            }
        }
        // Forget tracking for disks we no longer hold (torn down / fenced).
        last_success.retain(|k, _| still_held.contains(k));
    }
}

/// True iff `tokens` still maps `project` to EXACTLY `token`. The self-fence guard: a
/// concurrent (re)deploy may have rotated the disk token (a fresh, higher-epoch token
/// renewed independently) while a stale renewal was in flight; fencing then would kill
/// the live, freshly-attached VM — a self-inflicted outage. Fence only the holder of
/// the precise token whose renewal was lost.
pub(crate) fn token_still_held(
    tokens: &HashMap<String, FenceToken>,
    project: &str,
    token: &FenceToken,
) -> bool {
    tokens.get(project) == Some(token)
}

/// Self-fence one project whose data-disk lease was lost: kill its Firecracker (stop
/// writes) and detach the disk, so a survivor can safely take over. Guarded on token
/// identity so a redeploy that rotated the token is never killed.
pub(crate) async fn self_fence_project(
    platform: &Arc<Mutex<PlatformState>>,
    project_id: &str,
    lost_token: &FenceToken,
) {
    // Take the VM out under the lock, but ONLY if we still hold exactly the lost token.
    let (vm, data_disk) = {
        let mut plat = platform.lock().await;
        if !token_still_held(&plat.disk_tokens, project_id, lost_token) {
            // Token rotated (redeploy) or already released (teardown) — not ours to fence.
            return;
        }
        // Don't fence a project mid-transition: an in-flight hibernate owns the VM handle
        // (so we can neither kill it nor safely detach the loop device its FC still maps),
        // and wake re-fences on its own. We cannot act here; during the transition a
        // survivor is instead held off by the attach-time storage fence (LocalLoop liveness
        // / Ceph blocklist on `attach_rwo`) until the op releases the token, after which the
        // next tick self-fences if still lost. (A genuine loss is NOT dropped — FenceNow
        // recurs every tick and bypasses the deadline.) NB the guest may still be writing
        // in hibernate's brief pre-pause window, so this is defense-in-depth deferral, not
        // a "no writes" guarantee — the storage-layer fence is the actual backstop.
        if matches!(
            plat.vm_states.get(project_id),
            Some(VmLifecycle::Hibernating) | Some(VmLifecycle::Waking)
        ) {
            return;
        }
        tracing::error!(project = %project_id, scope = %lost_token.scope, epoch = lost_token.epoch,
               "DATA-DISK LEASE LOST — self-fencing: killing Firecracker before any survivor attaches");
        // Drop our claim first so no other path still treats us as the holder. Remove the
        // re-adoption record too: the FC is about to be killed, so a future start must NOT
        // re-adopt it (it'll cold-boot once the lease situation clears).
        plat.disk_tokens.remove(project_id);
        handoff::remove(&plat.data_dir.join("run"), project_id);
        plat.vm_states.remove(project_id);
        plat.vm_incarnations.retire(project_id);
        plat.vm_rootfs_hashes.remove(project_id);
        (plat.vms.remove(project_id), plat.data_disk.clone())
    };
    // Kill the FC HARD — the safety action — before anything slow.
    if let Some(mut vm) = vm
        && let Err(e) = vm.stop().await
    {
        tracing::error!(project = %project_id, error = %e, "self-fence: failed to kill Firecracker");
    }
    // Best-effort detach so the survivor's attach is unblocked (the lease is already lost).
    let _ = data_disk.detach(project_id).await;
}

/// Data-disk lease TTL — the failover horizon. With the node-local FlockLease it is moot
/// (the lock is held for the life of the process); with a distributed lease (HA) it is
/// the etcd grant TTL: a crashed/partitioned holder's key expires this long after its
/// LAST SUCCESSFUL renew, which is the earliest a survivor may take the disk. The
/// disk-fence loop self-fences once a disk's last success ages past [`DISK_FENCE_DEADLINE`]
/// — anchored at last success (NOT first-observed-failure) and with each renew bounded by
/// [`RENEW_RPC_TIMEOUT`] — so the safety relation holds even under a blackhole partition:
///   DISK_FENCE_DEADLINE + (DISK_RENEW_INTERVAL + RENEW_RPC_TIMEOUT) + kill  <  DISK_LEASE_TTL
/// i.e. the holder kills its Firecracker before its lease can expire and admit a survivor.
pub(crate) const DISK_LEASE_TTL: Duration = Duration::from_secs(30);

/// How often the disk-fence loop re-asserts (renews) each held data-disk lease.
pub(crate) const DISK_RENEW_INTERVAL: Duration = Duration::from_secs(5);

/// Self-fence once a disk's time-since-last-successful-renew reaches this (fail closed).
/// A genuine supersession ([`SubstrateError::Fenced`]) self-fences immediately regardless.
/// Satisfies the relation on [`DISK_LEASE_TTL`]: long enough that a brief blip never kills
/// a live VM, short enough to beat lease-expiry/takeover by a margin.
pub(crate) const DISK_FENCE_DEADLINE: Duration = Duration::from_secs(15);

/// Per-attempt bound on a lease renew RPC. Under a network blackhole an unbounded etcd
/// renew (`get` + keepalive) can hang for minutes on TCP retransmit, which would stall the
/// fence loop past the lease TTL and let a survivor attach over a still-live writer.
/// Bounding each attempt turns a hang into a prompt transient error, so the deadline clock
/// (anchored at last success) keeps advancing and the host self-fences in time.
pub(crate) const RENEW_RPC_TIMEOUT: Duration = Duration::from_secs(2);

/// HA P2 — the split-brain GATE. Deterministic tests of the COORDINATION layer of the
/// data-disk fence the self-fence (`disk_fence_loop`/`self_fence_project`) and the
/// restore-path fence rely on: that the lease + epoch + renew-or-die logic admit at most
/// one writer per disk scope. **GATE: the coordination layer must be green before any
/// failover automation (P3+) is wired** — the cluster BLOCK-DEVICE exclusivity gate (a
/// live partition actually being prevented from writing) is the substrate's on-box test
/// plus the EtcdLease 2-host run noted below.
///
/// Admission model: a host may write a disk iff it still holds the lease. Production
/// de-admits (self-fences) on a renew that is `Fenced` (superseded) or that stays failing
/// past the grace window — see `evaluate_renew`, unit-tested for the transient-vs-fenced
/// discrimination by `renew_evaluation_discriminates_fenced_from_transient`. The four
/// scenarios below walk the split-brain space and assert `at most one host is admitted at
/// any moment`.
///
/// Coverage boundary (honest — not silently capped):
///  - These run against the node-local `FlockLease` (no root, CI-deterministic) and so
///    prove the COORDINATION layer (mutual exclusion, de-admission on loss, epoch
///    monotonicity). A voluntary `release` models a definitive (`Fenced`) loss.
///  - The transient-blip-vs-real-loss discrimination (so an etcd hiccup never kills a
///    live VM) is covered separately + deterministically by `evaluate_renew`'s unit test.
///  - The real BLOCK-DEVICE exclusivity (a live prior writer blocks `attach_rwo`) is the
///    substrate's on-box `attach_refuses_while_prior_writer_is_alive`.
///  - The live-partition case (holder still alive while the AUTHORITY expired its lease)
///    needs the distributed `EtcdLease` + a real 2-host/partition run — the rented-
///    hardware last mile, NOT proven here.
#[cfg(test)]
mod split_brain_gate {
    use jkbase_substrate::{FenceToken, FlockLease, Lease, SubstrateError};
    use std::time::Duration;

    const TTL: Duration = Duration::from_secs(15);

    fn leases_dir(tag: &str) -> std::path::PathBuf {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!("jkbase-gate-{tag}-{nanos}"))
    }

    /// The production admission gate: a host may write iff its lease token still renews.
    async fn may_write(lease: &FlockLease, token: &FenceToken) -> bool {
        lease.renew(token, TTL).await.is_ok()
    }

    /// S1 — racing writers: two hosts contend for one disk; mutual exclusion admits
    /// at most one. The loser never even gets a token.
    #[tokio::test]
    async fn racing_writers_admit_at_most_one() {
        let dir = leases_dir("race");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        // host-b races for the same disk and is refused while a live holder owns it.
        assert!(matches!(
            b.acquire("disk-p", "host-b", TTL).await,
            Err(SubstrateError::LeaseHeld { .. })
        ));
        assert!(may_write(&a, &ta).await, "exactly one admitted writer (a)");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S2 — lease loss mid-write: the holder's admission is revoked the instant it loses
    /// the lease (→ self-fence), and a survivor can be admitted ONLY afterwards, with a
    /// strictly higher epoch. There is never a moment with two admitted writers.
    #[tokio::test]
    async fn lease_loss_revokes_admission_before_survivor_is_admitted() {
        let dir = leases_dir("loss");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        assert!(may_write(&a, &ta).await, "a is the writer");
        // While a holds, the survivor CANNOT acquire — so two are never admitted at once.
        assert!(b.acquire("disk-p", "host-b", TTL).await.is_err());

        // a loses the lease (partition / TTL expiry ≈ the OS releasing its flock).
        a.release(&ta).await.unwrap();
        assert!(
            !may_write(&a, &ta).await,
            "a self-fences the instant it loses the lease"
        );
        // Only NOW can the survivor be admitted, with a strictly higher epoch.
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        assert!(tb.epoch > ta.epoch);
        assert!(may_write(&b, &tb).await);
        assert!(
            !may_write(&a, &ta).await,
            "deposed a stays de-admitted (no double writer)"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S3 — TTL clock skew: authority is by epoch (monotonic, lease-issued), NOT by any
    /// host's wall clock. A clock-skewed old host's token can never supersede the newer
    /// holder's, so skew cannot revive a stale writer.
    #[tokio::test]
    async fn clock_skew_cannot_revive_a_stale_token() {
        let dir = leases_dir("skew");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        a.release(&ta).await.unwrap();
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        assert!(tb.supersedes(&ta).unwrap(), "newer epoch supersedes");
        assert!(
            !ta.supersedes(&tb).unwrap(),
            "a clock-skewed stale token never supersedes the live holder"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// S4 — zombie double-write: a hung old writer that still 'believes' it holds the
    /// disk after a takeover is denied on both axes — its stale token neither renews nor
    /// supersedes the live holder.
    #[tokio::test]
    async fn zombie_holder_cannot_write_after_takeover() {
        let dir = leases_dir("zombie");
        // Shared source_id = the (single) lease authority — so tokens are globally
        // comparable by epoch, as a distributed lease (etcd) issues them; distinct
        // `holder`s on acquire identify the two hosts. Mutual exclusion still comes
        // from the two separate flock handles over the shared lock file.
        let a = FlockLease::open(dir.clone(), "cluster").unwrap();
        let b = FlockLease::open(dir.clone(), "cluster").unwrap();
        let ta = a.acquire("disk-p", "host-a", TTL).await.unwrap();
        // a hangs/partitions; its flock is released (OS on crash, modelled by release).
        a.release(&ta).await.unwrap();
        let tb = b.acquire("disk-p", "host-b", TTL).await.unwrap();
        // The zombie keeps trying to use its stale token — denied both ways:
        assert!(
            !may_write(&a, &ta).await,
            "stale token can't renew → denied admission"
        );
        assert!(
            !ta.supersedes(&tb).unwrap(),
            "stale token can't supersede the live holder"
        );
        assert!(
            may_write(&b, &tb).await,
            "the live holder is the sole writer"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jkbase_substrate::{FenceToken, SubstrateError};

    #[tokio::test]
    async fn flock_lease_elects_single_leader() {
        // The election primitive (HA P2): with a SHARED lease backend, exactly one host
        // holds `cluster-leader` at a time; a contender wins only after the holder
        // releases (≈ the holder dying, which the OS does for flock), with a strictly
        // higher epoch. Two FlockLease instances over one leases dir = a single-box sim
        // cluster of two hosts.
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let leases = std::env::temp_dir().join(format!("jkbase-leader-{nanos}"));
        let a = jkbase_substrate::FlockLease::open(leases.clone(), "host-a").unwrap();
        let b = jkbase_substrate::FlockLease::open(leases.clone(), "host-b").unwrap();
        let ttl = Duration::from_secs(15);

        // host-a wins leadership.
        let ta = a.acquire(LEADER_SCOPE, "host-a", ttl).await.unwrap();
        // host-b cannot while a live holder owns it.
        assert!(matches!(
            b.acquire(LEADER_SCOPE, "host-b", ttl).await,
            Err(SubstrateError::LeaseHeld { .. })
        ));
        // host-a re-asserts (the loop's keepalive) — same token, no epoch churn.
        assert_eq!(a.renew(&ta, ttl).await.unwrap().epoch, ta.epoch);

        // host-a steps down (≈ crash); host-b now wins, with a higher epoch (fence
        // monotonicity across the leadership change).
        a.release(&ta).await.unwrap();
        let tb = b.acquire(LEADER_SCOPE, "host-b", ttl).await.unwrap();
        assert!(
            tb.epoch > ta.epoch,
            "new leader's epoch must supersede the old"
        );
        // The deposed host can no longer renew its stale token.
        assert!(a.renew(&ta, ttl).await.is_err());

        let _ = std::fs::remove_dir_all(&leases);
    }

    #[test]
    fn renew_evaluation_discriminates_fenced_from_transient() {
        // The HIGH-fix core (HA P2): a renew error must NOT be treated uniformly — a
        // transient blip/timeout must never self-fence a live VM / flap leadership, and the
        // deadline is anchored at the LAST SUCCESS (the clock the lease TTL runs on).
        let deadline = Duration::from_secs(12);
        let t0 = Instant::now();
        let tok = FenceToken {
            scope: "disk-p".into(),
            epoch: 1,
            holder: "host-a".into(),
            source_id: "cluster".into(),
        };
        let ok: Result<FenceToken, SubstrateError> = Ok(tok);
        let fenced: Result<FenceToken, SubstrateError> = Err(SubstrateError::Fenced {
            scope: "disk-p".into(),
        });
        // A timed-out renew is surfaced as Backend, indistinguishable here from any blip.
        let transient: Result<FenceToken, SubstrateError> = Err(SubstrateError::Backend(
            "etcd unreachable / timed out".into(),
        ));

        // A confirmed renew holds (resets the last-success clock).
        assert_eq!(evaluate_renew(&ok, t0, t0, deadline), FenceDecision::Hold);
        // A genuine supersession fences IMMEDIATELY, even just after a success.
        assert_eq!(
            evaluate_renew(&fenced, t0, t0 + Duration::from_secs(1), deadline),
            FenceDecision::FenceNow
        );
        // A fresh transient blip (last success just now) → keep waiting; one dropped
        // packet never kills a live VM.
        assert_eq!(
            evaluate_renew(&transient, t0, t0, deadline),
            FenceDecision::KeepWaiting
        );
        // Transient, last success still within the deadline → keep waiting.
        assert_eq!(
            evaluate_renew(&transient, t0, t0 + Duration::from_secs(11), deadline),
            FenceDecision::KeepWaiting
        );
        // Transient and last success aged past the deadline → fail closed before the
        // lease TTL can expire and admit a survivor.
        assert_eq!(
            evaluate_renew(&transient, t0, t0 + Duration::from_secs(12), deadline),
            FenceDecision::FenceNow
        );
    }

    #[test]
    fn self_fence_guard_only_fences_the_exact_lost_token() {
        // The split-brain safety guard (HA P2): fence ONLY the holder of the precise
        // token whose renewal was lost, so a redeploy that rotated the token (a live,
        // freshly-attached VM) is never killed.
        let tok = |scope: &str, epoch: u64| FenceToken {
            scope: scope.into(),
            epoch,
            holder: "host-a".into(),
            source_id: "src".into(),
        };
        let mut tokens: HashMap<String, FenceToken> = HashMap::new();
        tokens.insert("p".to_string(), tok("p", 1));

        // Exact token still held → fence it.
        assert!(token_still_held(&tokens, "p", &tok("p", 1)));
        // Rotated by a redeploy (higher epoch) → do NOT fence (would kill the live VM).
        assert!(!token_still_held(&tokens, "p", &tok("p", 2)));
        // Same epoch but different holder/source → not the same token → do not fence.
        assert!(!token_still_held(
            &tokens,
            "p",
            &FenceToken {
                scope: "p".into(),
                epoch: 1,
                holder: "host-b".into(),
                source_id: "src".into()
            }
        ));
        // Already torn down → nothing to fence.
        tokens.remove("p");
        assert!(!token_still_held(&tokens, "p", &tok("p", 1)));
    }
}
